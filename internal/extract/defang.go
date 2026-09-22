package extract

import "strings"

// Defang renders an IOC in ASTRA's write-up convention: "://" becomes
// "[:]//", and only the final dot in a host (the one separating the domain
// from its TLD) is bracketed — e.g. "updates.acelauncher[.]com", not
// "updates[.]acelauncher[.]com". IPv4 addresses bracket every dot, since
// there's no equivalent "TLD" boundary to single out. This matches the
// existing pattern in malware/acelauncher.txt rather than inventing a new
// convention.
func (i IOC) Defang() string {
	switch i.Type {
	case TypeIPv4:
		return strings.ReplaceAll(i.Value, ".", "[.]")
	case TypeURL:
		return defangURL(i.Value)
	case TypeDomain:
		return defangHost(i.Value)
	default:
		return i.Value
	}
}

func defangURL(u string) string {
	const sep = "://"
	idx := strings.Index(u, sep)
	if idx == -1 {
		return u
	}
	scheme, rest := u[:idx], u[idx+len(sep):]

	hostEnd := strings.IndexAny(rest, "/?#")
	host, tail := rest, ""
	if hostEnd != -1 {
		host, tail = rest[:hostEnd], rest[hostEnd:]
	}

	return scheme + "[:]//" + defangHost(host) + tail
}

func defangHost(host string) string {
	i := strings.LastIndex(host, ".")
	if i == -1 {
		return host
	}
	return host[:i] + "[.]" + host[i+1:]
}
