namespace Socks5Wrap.Socks5
{
    internal enum SocksRequestCommand : byte
    {
        Connect = 0x01,
        Bind = 0x02,
        UdpAssociate = 0x03
    }
}
