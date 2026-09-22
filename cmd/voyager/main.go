// Command voyager finds and fingerprints suspected C2 infrastructure, and
// extracts candidate IOCs from analyzed malware samples.
//
// Subcommands:
//
//	voyager extract   — pull candidate IOCs (IPs/domains/URLs) out of a sample's strings
//	voyager discover  — find candidate hosts via Shodan (new hosts, not yet verified)
//	voyager scan      — fingerprint one already-known host:port directly
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		topLevelUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "extract":
		runExtract(os.Args[2:])
	case "discover":
		runDiscover(os.Args[2:])
	case "scan":
		runScan(os.Args[2:])
	case "-h", "--help", "help":
		topLevelUsage()
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n\n", os.Args[1])
		topLevelUsage()
		os.Exit(2)
	}
}

func topLevelUsage() {
	fmt.Fprintf(os.Stderr, `Usage: voyager <command> [flags]

Commands:
  extract    pull candidate IOCs out of a malware sample's strings
  discover   find candidate C2 hosts across the internet via Shodan
  scan       fingerprint one known host:port directly (through Tor)

Run "voyager <command> -h" for command-specific flags.
`)
}
