namespace Socks5Wrap.Net.Socks5
{
    public enum SocksMethodAuth
    {
        NoAuthRequired = 0x00,
        GSSAPI = 0x01,
        UsernamePassword = 0x02,
        NoAcceptableMethods = 0xFF
    }
}
