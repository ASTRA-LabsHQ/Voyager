// Package fingerprint detects known C2 framework listeners from network-level
// artifacts (TLS fingerprints, banners, etc). Each detection technique lives
// in its own Fingerprinter so new ones can be added without touching existing
// code or the CLI.
package fingerprint

import "context"

// Match is a single positive hit: the observed value matched a known,
// sourced C2 signature.
type Match struct {
	Framework string // e.g. "Cobalt Strike"
	Indicator string // detection technique, e.g. "JARM"
	Value     string // the raw fingerprint value that matched
	Note      string // caveats about this signal (shared hashes, false-positive history, etc)
	Source    string // where the known-signature data came from
}

// Result is the outcome of running one Fingerprinter against a target.
type Result struct {
	Raw     string  // the raw computed fingerprint value, kept even on no match (useful for manual review/enrichment)
	Matches []Match // known-C2 signatures the raw value matched, if any
}

// Fingerprinter probes a single host:port and reports any known-C2 matches.
type Fingerprinter interface {
	Name() string
	Detect(ctx context.Context, host string, port int) (Result, error)
}
