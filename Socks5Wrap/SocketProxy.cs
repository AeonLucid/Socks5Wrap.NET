﻿using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Socks5Wrap.Socks5;

namespace Socks5Wrap
{
    /// <summary>
    ///     This class is not reusable.
    ///     You have to create a new instance for each connection / attempt.
    /// </summary>
    public class SocketProxy
    {
        private readonly byte[] _buffer;

        public SocketProxy(EndPoint proxyEndpoint, EndPoint destination)
        {
            _buffer = new byte[512];

            ProxyEndpoint = proxyEndpoint;
            Destination = destination;
            Socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        }

        /// <summary>
        ///     The SOCKS5 server.
        /// </summary>
        public EndPoint ProxyEndpoint { get; }

        /// <summary>
        ///     The destination for the SOCKS5 proxy.
        /// </summary>
        public EndPoint Destination { get; internal set; }

        /// <summary>
        ///     The SOCKS5 connection <see cref="Socket"/>.
        /// </summary>
        public Socket Socket { get; internal set; }

        public SocksMethodAuth? MethodAuth { get; internal set; }

        public SocksReply? Reply { get; internal set; }

        public async Task<(SocketProxyResult, Socket)> ConnectToAsync(TimeSpan connectTimeout)
        {
            // Connect to the proxy.
            var result = Socket.BeginConnect(ProxyEndpoint, null, null);
            var success = result.AsyncWaitHandle.WaitOne(connectTimeout);
            if (!success)
            {
                Socket.Dispose();
                return (SocketProxyResult.TimeoutConnect, null);
            }

            Socket.EndConnect(result);

            // Exchange data with the proxy.
            var tasks = new Func<Task<SocketProxyResult>>[]
            {
                DoMethodsAsync,
                DoAuthAsync,
                DoConnectAsync
            };

            foreach (var task in tasks)
            {
                var response = await task();
                if (response != SocketProxyResult.Ok)
                {
                    Socket.Dispose();
                    return (response, null);
                }
            }

            return (SocketProxyResult.Ok, Socket);
        }

        private async Task<SocketProxyResult> DoMethodsAsync()
        {
            // The client connects to the server,
            // and sends a version identifier / method selection message.
            var methodsBuffer = new byte[]
            {
                (byte) SocksVersion.Five, // VER
                0x01, // NMETHODS
                (byte) SocksMethodAuth.NoAuthRequired // Methods
            };

            await Socket.SendAsync(new ArraySegment<byte>(methodsBuffer), SocketFlags.None);

            // The server selects from one of the methods given in METHODS,
            // and sends a METHOD selection message:
            var receivedBytes = await Socket.ReceiveAsync(new ArraySegment<byte>(_buffer), SocketFlags.None);
            if (receivedBytes != 2)
            {
                return SocketProxyResult.MethodInvalidLength;
            }

            MethodAuth = (SocksMethodAuth)_buffer[1];

            return SocketProxyResult.Ok;
        }

        private Task<SocketProxyResult> DoAuthAsync()
        {
            if (!MethodAuth.HasValue)
            {
                throw new ArgumentException("No SOCKS5 auth method has been set.");
            }

            // The client and server then enter a method-specific sub-negotiation.
            switch (MethodAuth.Value)
            {
                case SocksMethodAuth.NoAuthRequired:
                    break;

                case SocksMethodAuth.GSSAPI:
                    throw new NotSupportedException("GSSAPI is not implemented.");

                case SocksMethodAuth.UsernamePassword:
                    throw new NotSupportedException("UsernamePassword is not implemented.");

                // If the selected METHOD is X'FF', none of the methods listed by the
                // client are acceptable, and the client MUST close the connection
                case SocksMethodAuth.NoAcceptableMethods:
                    Socket.Dispose();
                    return Task.FromResult(SocketProxyResult.MethodNotAcceptable);

                default:
                    Socket.Dispose();
                    throw new ArgumentOutOfRangeException();
            }

            return Task.FromResult(SocketProxyResult.Ok);
        }

        private async Task<SocketProxyResult> DoConnectAsync()
        {
            // Once the method-dependent subnegotiation has completed,
            // the client sends the request details.
            var dstIsHostname = Destination is DnsEndPoint;

            var dstAddress = dstIsHostname
                ? Encoding.ASCII.GetBytes(((DnsEndPoint) Destination).Host)
                : ((IPEndPoint) Destination).Address.GetAddressBytes();

            var dstPort = dstIsHostname
                ? ((DnsEndPoint) Destination).Port
                : ((IPEndPoint) Destination).Port;

            var requestBuffer = Destination is DnsEndPoint
                ? new byte[7 + dstAddress.Length]
                : new byte[6 + dstAddress.Length];

            requestBuffer[0] = (byte) SocksVersion.Five;
            requestBuffer[1] = (byte) SocksRequestCommand.Connect;

            if (dstIsHostname)
            {
                requestBuffer[3] = (byte) SocksRequestAddressType.FQDN;
                requestBuffer[4] = (byte) dstAddress.Length;

                for (var i = 0; i < dstAddress.Length; i++)
                {
                    requestBuffer[5 + i] = dstAddress[i];
                }

                requestBuffer[5 + dstAddress.Length] = (byte) (dstPort >> 8);
                requestBuffer[6 + dstAddress.Length] = (byte) dstPort;
            }
            else
            {
                requestBuffer[3] = dstAddress.Length == 4 
                    ? (byte) SocksRequestAddressType.IPv4
                    : (byte) SocksRequestAddressType.IPv6;

                for (var i = 0; i < dstAddress.Length; i++)
                {
                    requestBuffer[4 + i] = dstAddress[i];
                }

                requestBuffer[4 + dstAddress.Length] = (byte) (dstPort >> 8);
                requestBuffer[5 + dstAddress.Length] = (byte) dstPort;
            }

            await Socket.SendAsync(new ArraySegment<byte>(requestBuffer), SocketFlags.None);

            // The server evaluates the request, and returns a reply.
            // - First we read VER, REP, RSV & ATYP
            var received = await Socket.ReceiveAsync(new ArraySegment<byte>(_buffer, 0, 4), SocketFlags.None);
            if (received != 4)
            {
                if (received >= 2)
                {
                    Reply = (SocksReply)_buffer[1];
                }

                return SocketProxyResult.ReplyInvalidLength;
            }

            // - Now we check if the reply was positive.
            Reply = (SocksReply)_buffer[1];

            if (Reply != SocksReply.Succeeded)
            {
                return SocketProxyResult.ReplyInvalid;
            }

            // - Consume rest of the SOCKS5 protocol so the next read will give application data.
            var atyp = (SocksRequestAddressType) _buffer[3];
            int atypSize;
            int read;

            switch (atyp)
            {
                case SocksRequestAddressType.IPv4:
                    atypSize = 6;
                    read = await Socket.ReceiveAsync(new ArraySegment<byte>(_buffer, 0, atypSize), SocketFlags.None);
                    break;
                case SocksRequestAddressType.IPv6:
                    atypSize = 18;
                    read = await Socket.ReceiveAsync(new ArraySegment<byte>(_buffer, 0, atypSize), SocketFlags.None);
                    break;
                case SocksRequestAddressType.FQDN:
                    atypSize = 1;
                    await Socket.ReceiveAsync(new ArraySegment<byte>(_buffer, 0, atypSize), SocketFlags.None);

                    atypSize = _buffer[0] + 2;
                    read = await Socket.ReceiveAsync(new ArraySegment<byte>(_buffer, 0, atypSize), SocketFlags.None);
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            if (read != atypSize)
            {
                return SocketProxyResult.ReplyInvalid;
            }

            return SocketProxyResult.Ok;
        }
    }
}