package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ASTRA-LabsHQ/Voyager/internal/discovery"
	"github.com/ASTRA-LabsHQ/Voyager/internal/fingerprint"
)

func runDiscover(args []string) {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	jarmHash := fs.String("jarm", "", "raw JARM hash to search Shodan for")
	framework := fs.String("framework", "", `C2 framework name to search for, e.g. "Cobalt Strike" (looks up every known JARM hash for it)`)
	rawQuery := fs.String("query", "", "raw Shodan search query, overrides -jarm/-framework")
	limit := fs.Int("limit", 100, "max candidates to return per query")
	shodanKey := fs.String("shodan-key", os.Getenv("SHODAN_API_KEY"), "Shodan API key (default: $SHODAN_API_KEY)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: voyager discover [flags]

Finds candidate C2 hosts across the internet by querying Shodan for known
fingerprints — it does not scan the internet itself. Results are unverified
leads: cross-check (e.g. "voyager scan") before treating anything as
confirmed live C2.

`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	queries, err := buildQueries(*rawQuery, *jarmHash, *framework)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		fs.Usage()
		os.Exit(2)
	}

	discoverer := discovery.NewShodanDiscoverer(*shodanKey)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	seen := map[string]bool{}
	total := 0
	for _, q := range queries {
		fmt.Printf("[*] querying %s for: %s\n", discoverer.Name(), q)

		candidates, err := discoverer.Discover(ctx, q, *limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "    error: %v\n", err)
			continue
		}

		if len(candidates) == 0 {
			fmt.Println("    no candidates")
			continue
		}

		for _, c := range candidates {
			key := fmt.Sprintf("%s:%d", c.IP, c.Port)
			if seen[key] {
				continue
			}
			seen[key] = true
			total++

			fmt.Printf("    %-21s org=%q asn=%s\n", key, c.Org, c.ASN)
		}
	}

	fmt.Printf("\n%d unverified candidate(s) found. Cross-check before treating any as confirmed C2 — a shared fingerprint doesn't guarantee the framework, and Shodan's data can be stale.\n", total)
}

// buildQueries turns the mutually-exclusive -query/-jarm/-framework flags
// into one or more Shodan search queries.
func buildQueries(rawQuery, jarmHash, framework string) ([]string, error) {
	switch {
	case rawQuery != "":
		return []string{rawQuery}, nil

	case jarmHash != "":
		return []string{fmt.Sprintf("ssl.jarm:%q", jarmHash)}, nil

	case framework != "":
		hashes := fingerprint.FrameworkJARMHashes(framework)
		if len(hashes) == 0 {
			return nil, fmt.Errorf("no known JARM hash for framework %q", framework)
		}
		queries := make([]string, len(hashes))
		for i, h := range hashes {
			queries[i] = fmt.Sprintf("ssl.jarm:%q", h)
		}
		return queries, nil

	default:
		return nil, fmt.Errorf("specify one of -query, -jarm, or -framework")
	}
}
