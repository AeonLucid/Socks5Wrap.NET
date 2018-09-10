using System;
using System.Net;
using System.Threading.Tasks;
using Socks5Wrap.Net;

namespace Socks5Wrap.ConsoleTest
{
    internal class Program
    {
        private static async Task Main()
        {
            var proxyIp = Environment.GetEnvironmentVariable("PROXY_IP");
            var proxyPort = Environment.GetEnvironmentVariable("PROXY_PORT");

            var destIp = Environment.GetEnvironmentVariable("DEST_IP");
            var destPort = Environment.GetEnvironmentVariable("DEST_PORT");

            var socketProxy = new SocketProxy(proxyIp, int.Parse(proxyPort), new IPEndPoint(IPAddress.Parse(destIp), int.Parse(destPort)));
            var socket = await socketProxy.ConnectToAsync();

            Console.WriteLine("Hello World!");
        }
    }
}
