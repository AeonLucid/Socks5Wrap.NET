namespace Socks5Wrap.Net.Socks5
{
    internal enum SocksAuthMethod
    {
        NoAuthRequired = 0x00,
        GSSAPI = 0x01,
        UsernamePassword = 0x02,
        NoAcceptableMethods = 0xFF
    }
}
