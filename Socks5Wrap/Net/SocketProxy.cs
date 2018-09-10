using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Socks5Wrap.Net.Socks5;

namespace Socks5Wrap.Net
{
    public class SocketProxy
    {
        public SocketProxy(string ip, int port)
        {
            Ip = ip;
            Port = port;
        }

        public string Ip { get; }

        public int Port { get; }

        public async Task<Socket> ConnectToAsync(EndPoint endpoint)
        {
            var buffer = new byte[1024];
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            
            // Connect to the SOCKS5 proxy.
            await socket.ConnectAsync(Ip, Port);

            // The client connects to the server,
            // and sends a version identifier / method selection message.
            var methodsBuffer = new byte[3]
            {
                (byte) SocksVersion.Five, // VER
                0x01, // NMETHODS
                0x00  // Methods
            };

            await socket.SendAsync(new ArraySegment<byte>(methodsBuffer), SocketFlags.None);

            // The server selects from one of the methods given in METHODS,
            // and sends a METHOD selection message:
            await socket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);
            
            var selectedMethod = (SocksAuthMethod) buffer[1];

            // The client and server then enter a method-specific sub-negotiation.
            switch (selectedMethod)
            {
                case SocksAuthMethod.NoAuthRequired:
                    // Skip?
                    break;

                case SocksAuthMethod.GSSAPI:
                    throw new NotSupportedException("GSSAPI is not implemented.");

                case SocksAuthMethod.UsernamePassword:
                    break;

                // If the selected METHOD is X'FF', none of the methods listed by the
                // client are acceptable, and the client MUST close the connection
                case SocksAuthMethod.NoAcceptableMethods:
                    socket.Dispose();
                    return null;

                default:
                    throw new ArgumentOutOfRangeException();
            }

            // Once the method-dependent subnegotiation has completed,
            // the client sends the request details.

            int requestBufferLength;
            byte[] requestBuffer;

            if (endpoint is IPEndPoint ipEndPoint)
            {
                var ipBytes = ipEndPoint.Address.GetAddressBytes();
                if (ipBytes.Length == 4)
                {
                    requestBufferLength = 10;
                    requestBuffer = new byte[]
                    {
                        (byte) SocksVersion.Five,
                        (byte) SocksRequestCommand.Connect,
                        0x00, // Reserved
                        (byte) SocksRequestAddressType.IPv4,
                        ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3],
                        (byte) (ipEndPoint.Port >> 8),
                        (byte) ipEndPoint.Port,
                    };
                }
                else if (ipBytes.Length == 16)
                {
                    requestBufferLength = 22;
                    requestBuffer = new byte[]
                    {
                        (byte) SocksVersion.Five,
                        (byte) SocksRequestCommand.Connect,
                        0x00, // Reserved
                        (byte) SocksRequestAddressType.IPv6,
                        ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3],
                        ipBytes[4], ipBytes[5], ipBytes[6], ipBytes[7],
                        ipBytes[8], ipBytes[9], ipBytes[10], ipBytes[11],
                        ipBytes[12], ipBytes[13], ipBytes[14], ipBytes[15],
                        (byte) (ipEndPoint.Port >> 8),
                        (byte) ipEndPoint.Port,
                    };
                }
                else
                {
                    throw new NotSupportedException($"Unsupported amount of ipBytes was found '{ipBytes.Length}'.");
                }
            }
            else if (endpoint is DnsEndPoint dnsEndPoint)
            {
                var dnsBytes = Encoding.ASCII.GetBytes(dnsEndPoint.Host);

                requestBufferLength = 7 + dnsBytes.Length;
                requestBuffer = new byte[262]; // Max amount of bytes

                requestBuffer[0] = (byte) SocksVersion.Five;
                requestBuffer[1] = (byte) SocksRequestCommand.Connect;
                requestBuffer[3] = (byte) SocksRequestAddressType.FQDN;
                requestBuffer[4] = (byte) dnsBytes.Length;

                Buffer.BlockCopy(dnsBytes, 0, requestBuffer, 5, dnsBytes.Length);

                requestBuffer[5 + dnsBytes.Length] = (byte) (dnsEndPoint.Port >> 8);
                requestBuffer[5 + dnsBytes.Length + 1] = (byte)dnsEndPoint.Port;
            }
            else
            {
                throw new NotSupportedException("Unsupported Endpoint implementation was given.");
            }

            await socket.SendAsync(new ArraySegment<byte>(requestBuffer, 0, requestBufferLength), SocketFlags.None);

            // The server evaluates the request, and returns a reply.
            await socket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);

            return null;
        }
    }
}
