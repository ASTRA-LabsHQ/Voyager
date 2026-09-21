// Package transport provides the dialer Voyager uses to reach suspected C2
// infrastructure: by default a SOCKS5 tunnel through a local Tor daemon, so
// probing adversary infrastructure doesn't come from (or get attributed
// back to) the research machine's own IP.
package transport

import (
	"fmt"
	"net"

	"golang.org/x/net/proxy"
)

// NewTorDialer returns a dialer that routes connections through a local Tor
// SOCKS5 proxy (torAddr, typically "127.0.0.1:9050"). It requires Tor to
// already be running — Voyager does not manage the Tor process itself.
func NewTorDialer(torAddr string) (proxy.Dialer, error) {
	dialer, err := proxy.SOCKS5("tcp", torAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("connect to tor at %s: %w", torAddr, err)
	}
	return dialer, nil
}

// NewDirectDialer bypasses Tor entirely. Only meant for local testing
// against a lab target — real scans against adversary infrastructure should
// always go through NewTorDialer.
func NewDirectDialer() proxy.Dialer {
	return proxy.Direct
}

// Reachable does a quick TCP dial to confirm the Tor SOCKS proxy is actually
// up before Voyager burns time on a 10-probe JARM sequence that will just
// fail silently otherwise.
func Reachable(torAddr string) error {
	conn, err := net.Dial("tcp", torAddr)
	if err != nil {
		return fmt.Errorf("tor SOCKS proxy not reachable at %s (is Tor running?): %w", torAddr, err)
	}
	conn.Close()
	return nil
}
