package extract

import "strings"

// commonTLDs is a deliberately non-exhaustive allowlist used to filter
// domain-shaped string matches down to plausible real domains, cutting out
// the most obvious noise from binary strings (file extensions, class/type
// names, XML namespaces). It is not a substitute for review — a domain
// with an unlisted TLD will simply be missed, and one with a listed TLD is
// still only a candidate.
var commonTLDs = map[string]bool{
	// generic
	"com": true, "net": true, "org": true, "edu": true, "gov": true, "mil": true, "int": true,
	"info": true, "biz": true, "name": true, "pro": true, "mobi": true, "asia": true,
	// tech/startup-favored gTLDs
	"io": true, "co": true, "app": true, "dev": true, "tech": true, "cloud": true,
	"digital": true, "online": true, "site": true, "website": true, "space": true,
	"store": true, "shop": true, "email": true, "host": true, "world": true, "life": true,
	"media": true, "agency": true, "solutions": true, "systems": true, "network": true,
	"software": true, "computer": true, "link": true, "live": true, "club": true,
	// cheap/free TLDs disproportionately favored by malware/phishing infra
	"xyz": true, "top": true, "icu": true, "click": true, "download": true, "stream": true,
	"science": true, "party": true, "review": true, "trade": true, "accountant": true,
	"faith": true, "date": true, "win": true, "bid": true, "loan": true, "men": true,
	"gdn": true, "cf": true, "ga": true, "gq": true, "ml": true, "tk": true, "work": true,
	"racing": true, "cricket": true, "webcam": true, "cam": true, "buzz": true, "rest": true,
	// common ccTLDs
	"us": true, "uk": true, "ca": true, "au": true, "nz": true, "ie": true, "de": true,
	"fr": true, "nl": true, "be": true, "ch": true, "at": true, "se": true, "no": true,
	"dk": true, "fi": true, "pl": true, "cz": true, "ro": true, "hu": true, "gr": true,
	"pt": true, "es": true, "it": true, "ru": true, "ua": true, "by": true, "kz": true,
	"tr": true, "ir": true, "sa": true, "ae": true, "il": true, "eg": true, "ke": true,
	"ng": true, "za": true, "cn": true, "hk": true, "tw": true, "jp": true, "kr": true,
	"sg": true, "th": true, "vn": true, "id": true, "my": true, "ph": true, "pk": true,
	"bd": true, "in": true, "mx": true, "br": true, "ar": true, "cl": true, "pe": true,
	"ve": true, "cc": true, "tv": true, "me": true, "ws": true, "to": true, "sh": true, "so": true,
}

func hasCommonTLD(host string) bool {
	i := strings.LastIndexByte(host, '.')
	if i == -1 {
		return false
	}
	return commonTLDs[strings.ToLower(host[i+1:])]
}
