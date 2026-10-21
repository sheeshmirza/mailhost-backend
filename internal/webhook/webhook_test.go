package webhook

import (
	"net"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip     string
		public bool
	}{
		// Public IPv4 addresses
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"104.26.10.12", true},

		// Private IPv4 ranges (RFC 1918)
		{"10.0.0.1", false},
		{"10.255.255.255", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.1.1", false},
		{"192.168.0.254", false},

		// Loopback (127.0.0.0/8)
		{"127.0.0.1", false},
		{"127.255.255.254", false},

		// Cloud Metadata & Link-Local (169.254.0.0/16)
		{"169.254.169.254", false},
		{"169.254.1.1", false},

		// Broadcast & Zero Network
		{"0.0.0.0", false},
		{"255.255.255.255", false},

		// Carrier-Grade NAT (CGNAT RFC 6598: 100.64.0.0/10)
		{"100.64.0.1", false},
		{"100.127.255.255", false},

		// Documentation & Benchmark ranges
		{"192.0.2.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"198.18.0.1", false},

		// Public IPv6
		{"2606:4700:4700::1111", true},
		{"2001:4860:4860::8888", true},

		// Private / Loopback IPv6
		{"::1", false},
		{"::", false},
		{"fc00::1", false},
		{"fd12:3456:789a:1::1", false},
		{"fe80::1", false},

		// IPv4-mapped IPv6 (SSRF bypass attempts)
		{"::ffff:127.0.0.1", false},
		{"::ffff:10.0.0.1", false},
		{"::ffff:169.254.169.254", false},
		{"::ffff:192.168.1.1", false},
		{"::ffff:8.8.8.8", true},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP %q", tt.ip)
		}
		if got := IsPublicIP(ip); got != tt.public {
			t.Errorf("IsPublicIP(%s) = %v, want %v", tt.ip, got, tt.public)
		}
	}
}

