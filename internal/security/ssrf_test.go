package security

import (
	"net"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"0.0.0.0",
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"169.254.169.254",
		"100.64.0.1",
		"192.0.2.1",
		"198.18.0.1",
		"203.0.113.1",
		"224.0.0.1",
		"240.0.0.1",
		"::1",
		"fe80::1",
		"fc00::1",
		"ff02::1",
		"2001:db8::1",
	}
	for _, raw := range blocked {
		if !isBlockedIP(net.ParseIP(raw)) {
			t.Errorf("reserved/local IP engellenmeliydi: %s", raw)
		}
	}

	for _, raw := range ofUnblockedIPs() {
		if isBlockedIP(net.ParseIP(raw)) {
			t.Errorf("public IP engellenmemeliydi: %s", raw)
		}
	}
}

func ofUnblockedIPs() []string {
	return []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"}
}
