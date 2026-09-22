// Package extract pulls candidate network IOCs (IPs, domains, URLs) out of
// a binary's printable strings. This is the original idea behind Voyager —
// done properly, against the raw sample, with automatic IP classification
// and Windows wide-char strings (which plain `strings` misses entirely and
// malware loaders lean on constantly for URLs).
//
// Everything this package produces is a *candidate*, not a confirmed
// indicator. String extraction from a binary pulls in real noise —
// Microsoft schema URLs, library version strings, XML namespaces — right
// alongside genuine C2 artifacts. Review before publishing.
package extract

// ASCIIStrings returns runs of printable ASCII bytes (0x20-0x7e) at least
// minLen long.
func ASCIIStrings(data []byte, minLen int) []string {
	var out []string
	start := -1
	for i, b := range data {
		if isPrintableASCII(b) {
			if start == -1 {
				start = i
			}
			continue
		}
		if start != -1 {
			if i-start >= minLen {
				out = append(out, string(data[start:i]))
			}
			start = -1
		}
	}
	if start != -1 && len(data)-start >= minLen {
		out = append(out, string(data[start:]))
	}
	return out
}

// UTF16LEStrings returns runs of printable UTF-16LE characters (a
// printable-ASCII low byte followed by a zero high byte) at least minLen
// characters long, decoded to plain ASCII. Windows binaries frequently
// store strings — including C2 URLs — as wide characters; ASCII-only
// extraction misses these entirely.
func UTF16LEStrings(data []byte, minLen int) []string {
	var out []string
	var cur []byte

	flush := func() {
		if len(cur) >= minLen {
			out = append(out, string(cur))
		}
		cur = nil
	}

	for i := 0; i+1 < len(data); i += 2 {
		lo, hi := data[i], data[i+1]
		if hi == 0x00 && isPrintableASCII(lo) {
			cur = append(cur, lo)
			continue
		}
		flush()
	}
	flush()

	return out
}

func isPrintableASCII(b byte) bool {
	return b >= 0x20 && b <= 0x7e
}
