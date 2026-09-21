package fingerprint

import "strings"

// FrameworkJARMHashes returns every known JARM hash observed for the given
// framework (case-insensitive substring match against knownJARM), so a
// caller can build a discovery query without hardcoding hash values itself.
func FrameworkJARMHashes(framework string) []string {
	needle := strings.ToLower(framework)
	var hashes []string
	for hash, sigs := range knownJARM {
		for _, sig := range sigs {
			if strings.Contains(strings.ToLower(sig.Framework), needle) {
				hashes = append(hashes, hash)
				break
			}
		}
	}
	return hashes
}
