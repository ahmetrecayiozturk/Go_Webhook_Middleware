package server

import "testing"

func TestIsValidHTTPURL(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		requireHTTPS bool
		want         bool
	}{
		{name: "https allowed", raw: "https://example.com/webhook", requireHTTPS: true, want: true},
		{name: "http rejected in production", raw: "http://example.com/webhook", requireHTTPS: true, want: false},
		{name: "http allowed in development", raw: "http://127.0.0.1:9000/webhook", requireHTTPS: false, want: true},
		{name: "missing host rejected", raw: "https:///webhook", requireHTTPS: true, want: false},
		{name: "unsupported scheme rejected", raw: "ftp://example.com/webhook", requireHTTPS: false, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidHTTPURL(tt.raw, tt.requireHTTPS); got != tt.want {
				t.Fatalf("isValidHTTPURL(%q, %v) = %v, want %v", tt.raw, tt.requireHTTPS, got, tt.want)
			}
		})
	}
}
