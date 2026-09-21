// Command voyager scans a target host for known C2 framework fingerprints.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/ASTRA-LabsHQ/Voyager/internal/fingerprint"
	"github.com/ASTRA-LabsHQ/Voyager/internal/transport"
	"golang.org/x/net/proxy"
)

func main() {
	var (
		torAddr = flag.String("tor-addr", "127.0.0.1:9050", "address of the local Tor SOCKS5 proxy")
		noTor   = flag.Bool("no-tor", false, "dial the target directly instead of through Tor (lab/testing use only)")
		timeout = flag.Duration("timeout", 5*time.Second, "per-probe network timeout")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <host:port>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Fingerprints a target for known C2 framework TLS listeners.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	host, portStr, err := net.SplitHostPort(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: expected host:port, got %q (%v)\n", flag.Arg(0), err)
		os.Exit(2)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid port %q: %v\n", portStr, err)
		os.Exit(2)
	}

	dialer, err := buildDialer(*torAddr, *noTor)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	fingerprinters := []fingerprint.Fingerprinter{
		fingerprint.NewJARMFingerprinter(dialer, *timeout),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for _, fp := range fingerprinters {
		fmt.Printf("[*] running %s against %s:%d\n", fp.Name(), host, port)

		result, err := fp.Detect(ctx, host, port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "    error: %v\n", err)
			continue
		}

		if len(result.Matches) == 0 {
			fmt.Printf("    no known-C2 match (raw=%s)\n", result.Raw)
			continue
		}

		for _, m := range result.Matches {
			fmt.Printf("    MATCH  framework=%q indicator=%s value=%s\n", m.Framework, m.Indicator, m.Value)
			fmt.Printf("           source=%s\n", m.Source)
			if m.Note != "" {
				fmt.Printf("           note=%s\n", m.Note)
			}
		}
	}
}

func buildDialer(torAddr string, noTor bool) (proxy.Dialer, error) {
	if noTor {
		fmt.Println("[!] --no-tor set: dialing directly, not through Tor")
		return transport.NewDirectDialer(), nil
	}

	if err := transport.Reachable(torAddr); err != nil {
		return nil, err
	}
	return transport.NewTorDialer(torAddr)
}
