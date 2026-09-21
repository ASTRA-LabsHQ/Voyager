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

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	torAddr := fs.String("tor-addr", "127.0.0.1:9050", "address of the local Tor SOCKS5 proxy")
	noTor := fs.Bool("no-tor", false, "dial the target directly instead of through Tor (lab/testing use only)")
	timeout := fs.Duration("timeout", 5*time.Second, "per-probe network timeout")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: voyager scan [flags] <host:port>\n\n")
		fmt.Fprintf(os.Stderr, "Fingerprints a single, already-known target for known C2 framework TLS listeners.\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}

	host, portStr, err := net.SplitHostPort(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: expected host:port, got %q (%v)\n", fs.Arg(0), err)
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
