package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/ASTRA-LabsHQ/Voyager/internal/extract"
)

func runExtract(args []string) {
	fs := flag.NewFlagSet("extract", flag.ExitOnError)
	minLen := fs.Int("min-len", 5, "minimum string length to consider")
	format := fs.String("format", "text", "output format: text, markdown, json")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: voyager extract [flags] <sample-path>

Scans a binary for printable strings (ASCII and UTF-16LE) and pulls out
candidate network IOCs — IPs, domains, URLs. These are CANDIDATES, not
confirmed indicators: binary strings pull in real noise (library URLs,
version strings, XML namespaces) alongside genuine artifacts. Review before
publishing.

Only ever run this against samples in an isolated analysis environment.

`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}

	path := fs.Arg(0)
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	var strs []string
	strs = append(strs, extract.ASCIIStrings(data, *minLen)...)
	strs = append(strs, extract.UTF16LEStrings(data, *minLen)...)

	iocs := extract.Extract(strs)

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(iocs); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "markdown":
		printExtractMarkdown(iocs)
	default:
		printExtractText(iocs, path)
	}
}

func printExtractText(iocs []extract.IOC, path string) {
	fmt.Printf("[*] %d candidate IOC(s) in %s\n\n", len(iocs), path)
	for _, i := range iocs {
		class := i.Class
		if class == "" {
			class = "-"
		}
		fmt.Printf("  %-7s %-9s %s\n", i.Type, class, i.Value)
	}
}

func printExtractMarkdown(iocs []extract.IOC) {
	fmt.Println("## Indicators of Compromise")
	fmt.Println()
	if len(iocs) == 0 {
		fmt.Println("_none found_")
		return
	}
	for _, i := range iocs {
		fmt.Printf("- %s\n", i.Defang())
	}
}
