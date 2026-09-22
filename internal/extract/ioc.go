package extract

import (
	"net"
	"regexp"
	"sort"
	"strings"
)

// Type identifies what kind of candidate an IOC is.
type Type string

const (
	TypeIPv4   Type = "ipv4"
	TypeDomain Type = "domain"
	TypeURL    Type = "url"
)

// IOC is one candidate indicator pulled from a sample's strings — a
// candidate, not a confirmed indicator. See package doc.
type IOC struct {
	Type  Type   `json:"type"`
	Value string `json:"value"`
	Class string `json:"class,omitempty"` // IPv4 only: public/private/loopback/other
}

var (
	ipv4Re = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b`)
	urlRe  = regexp.MustCompile(`\bhttps?://[^\s"'<>\\^` + "`" + `]+`)
	// A domain candidate: dot-separated labels ending in an alphabetic TLD
	// of 2+ characters. Deliberately permissive here — hasCommonTLD does
	// the real filtering.
	domainRe = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b`)
)

// Extract pulls IOC candidates out of a set of extracted strings (see
// ASCIIStrings/UTF16LEStrings), classifies IPv4 addresses, filters domain
// matches to a common-TLD allowlist, and deduplicates the result.
func Extract(strs []string) []IOC {
	seen := map[string]bool{}
	var out []IOC

	add := func(ioc IOC) {
		key := string(ioc.Type) + ":" + ioc.Value
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, ioc)
	}

	for _, s := range strs {
		for _, m := range urlRe.FindAllString(s, -1) {
			add(IOC{Type: TypeURL, Value: strings.TrimRight(m, ".,;:)")})
		}
		for _, m := range ipv4Re.FindAllString(s, -1) {
			ip := net.ParseIP(m)
			if ip == nil || ip.To4() == nil {
				continue
			}
			add(IOC{Type: TypeIPv4, Value: m, Class: classifyIPv4(ip)})
		}
		for _, m := range domainRe.FindAllString(s, -1) {
			m = strings.ToLower(m)
			if !hasCommonTLD(m) {
				continue
			}
			add(IOC{Type: TypeDomain, Value: m})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func classifyIPv4(ip net.IP) string {
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsPrivate():
		return "private"
	case ip.IsUnspecified(), ip.IsMulticast(), ip.Equal(net.IPv4bcast):
		return "other"
	default:
		return "public"
	}
}
