package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

var ErrBlockedTargetIP = errors.New("SSRF koruması: hedef özel/yerel ağ IP adresine çözümlendi")

// NewSafeDialContext, DNS çözümlemesi sonrası özel/yerel IP'lere bağlantıyı engeller
// ve Docker ortamlarında IPv6 'network is unreachable' hatasını önlemek için IPv4 öncelikli bağlanır.
func NewSafeDialContext(allowPrivate bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("geçersiz hedef adresi: %w", err)
		}

		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DNS çözümleme hatası: %w", err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("hedef host için IP bulunamadı: %s", host)
		}

		var ipv4s, ipv6s []net.IP
		for _, ipAddr := range ips {
			if !allowPrivate && isBlockedIP(ipAddr.IP) {
				return nil, fmt.Errorf("%w (%s -> %s)", ErrBlockedTargetIP, host, ipAddr.IP.String())
			}
			if ipAddr.IP.To4() != nil {
				ipv4s = append(ipv4s, ipAddr.IP)
			} else {
				ipv6s = append(ipv6s, ipAddr.IP)
			}
		}

		// IPv4 öncelikli bağlantı (Docker bridge ağlarında IPv6 egress yoktur)
		ordered := append(ipv4s, ipv6s...)
		var lastErr error
		for _, ip := range ordered {
			safeAddr := net.JoinHostPort(ip.String(), port)
			conn, dialErr := dialer.DialContext(ctx, network, safeAddr)
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
}

func isBlockedIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		addr, ok := netip.AddrFromSlice(ip4)
		if !ok {
			return true
		}
		addr = addr.Unmap()
		reservedV4 := []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/8"),
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("100.64.0.0/10"),
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("169.254.0.0/16"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.0.0.0/24"),
			netip.MustParsePrefix("192.0.2.0/24"),
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("198.18.0.0/15"),
			netip.MustParsePrefix("198.51.100.0/24"),
			netip.MustParsePrefix("203.0.113.0/24"),
			netip.MustParsePrefix("224.0.0.0/4"),
			netip.MustParsePrefix("240.0.0.0/4"),
		}
		for _, prefix := range reservedV4 {
			if prefix.Contains(addr) {
				return true
			}
		}
	}

	addr, ok := netip.AddrFromSlice(ip)
	if ok {
		addr = addr.Unmap()
		if addr.Is6() {
			reservedV6 := []netip.Prefix{
				netip.MustParsePrefix("::/128"),
				netip.MustParsePrefix("::1/128"),
				netip.MustParsePrefix("::ffff:0:0/96"),
				netip.MustParsePrefix("64:ff9b:1::/48"),
				netip.MustParsePrefix("100::/64"),
				netip.MustParsePrefix("2001:db8::/32"),
				netip.MustParsePrefix("fc00::/7"),
				netip.MustParsePrefix("fe80::/10"),
				netip.MustParsePrefix("ff00::/8"),
			}
			for _, prefix := range reservedV6 {
				if prefix.Contains(addr) {
					return true
				}
			}
		}
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}
