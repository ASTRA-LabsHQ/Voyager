// Package discovery finds candidate C2 hosts across the internet by
// querying services that have already scanned it — Shodan, Censys, etc —
// rather than probing address space directly. Voyager itself only ever
// touches a specific target once something else has already surfaced it as
// worth checking.
package discovery

import "context"

// Candidate is a host a Discoverer thinks is worth a closer look. It is
// unverified: the querying service's data can be stale, and a shared
// fingerprint (see internal/fingerprint's JARM caveats) doesn't guarantee
// the framework it's attributed to.
type Candidate struct {
	IP     string
	Port   int
	Source string // which service surfaced this, e.g. "shodan"
	Query  string // the exact query that matched
	Org    string
	ASN    string
}

// Discoverer searches a third-party internet-scanning service for hosts
// matching query, up to limit results.
type Discoverer interface {
	Name() string
	Discover(ctx context.Context, query string, limit int) ([]Candidate, error)
}
