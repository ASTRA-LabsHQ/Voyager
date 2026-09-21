package fingerprint

// JARMSignature is one known (hash -> framework) mapping.
type JARMSignature struct {
	Framework string
	Context   string // what was actually fingerprinted (language/runtime/version)
	Source    string
}

// knownJARM maps a JARM hash to every framework it has been observed on.
//
// JARM fingerprints the TLS stack a server's language/runtime uses, not the
// application itself — two unrelated tools built on the same runtime and TLS
// library (e.g. Python + aiohttp) produce the *same* hash. That's why several
// entries below share a value. Treat any single JARM hit as a candidate, not
// a conclusion: corroborate with a second, independent signal before calling
// something a live C2 listener. See the false-positive example noted below.
//
// Source: https://github.com/cedowens/C2-JARM (fetched 2026-09-21).
// Cross-reference: https://www.vanimpe.eu/2021/09/14/identify-malicious-servers-cobalt-strike-servers-with-jarm/
// documents a second, independently observed Cobalt Strike JARM hash that
// also matched 24 legitimate Zimbra servers out of 90 hits — the canonical
// example of why JARM alone is not sufficient.
var knownJARM = map[string][]JARMSignature{
	"2ad2ad0002ad2ad00042d42d000000ad9bf51cc3f5a1e29eecb81d0c7b06eb": {
		{Framework: "Mythic", Context: "python 3 w/aiohttp 3", Source: "cedowens/C2-JARM"},
		{Framework: "MacC2", Context: "python 3.8.2 w/aiohttp 3", Source: "cedowens/C2-JARM"},
		{Framework: "Shad0w", Context: "python 3.8 flask", Source: "cedowens/C2-JARM"},
		{Framework: "GRAT2 C2", Context: "python3 http.server", Source: "cedowens/C2-JARM"},
		{Framework: "SILENTTRINITY", Context: "ironpython", Source: "cedowens/C2-JARM"},
	},
	"07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d": {
		{Framework: "Metasploit", Context: "ssl listener, ruby 2.7.0p0", Source: "cedowens/C2-JARM"},
	},
	"07d14d16d21d21d07c42d43d000000f50d155305214cf247147c43c0f1a823": {
		{Framework: "Metasploit", Context: "ssl listener, ruby", Source: "cedowens/C2-JARM"},
	},
	"07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": {
		{Framework: "Cobalt Strike", Context: "team server, Java 11", Source: "cedowens/C2-JARM"},
	},
	"05d02d20d21d20d05c05d02d05d20dd7fc4c7c6ef19b77a4ca0787979cdc13": {
		{Framework: "Cobalt Strike", Context: "team server (variant observed in the wild)", Source: "vanimpe.eu — 66/90 hits confirmed, 24/90 were Zimbra false positives"},
	},
	"29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38": {
		{Framework: "Merlin", Context: "go 1.15.2 linux/amd64", Source: "cedowens/C2-JARM"},
	},
	"00000000000000000041d00000041d9535d5979f591ae8e547c5e5743e5b64": {
		{Framework: "Deimos", Context: "go 1.15.2 linux/amd64 w/gorilla/websocket", Source: "cedowens/C2-JARM"},
	},
	"2ad2ad0002ad2ad22c42d42d000000faabb8fd156aa8b4d8a37853e1063261": {
		{Framework: "MacC2", Context: "python 3.8.6 w/aiohttp 3", Source: "cedowens/C2-JARM"},
		{Framework: "PoshC2", Context: "python3 http.server", Source: "cedowens/C2-JARM"},
	},
	"2ad000000000000000000000000000eeebf944d0b023a00f510f06a29b4f46": {
		{Framework: "MacShellSwift / MacShell", Context: "python 3.8.6 socket", Source: "cedowens/C2-JARM"},
	},
	"2ad2ad0002ad2ad00041d2ad2ad41da5207249a18099be84ef3c8811adc883": {
		{Framework: "Sliver", Context: "go 1.15.2 linux/amd64", Source: "cedowens/C2-JARM"},
	},
	"20d14d20d21d20d20c20d14d20d20daddf8a68a1444c74b6dbe09910a511e6": {
		{Framework: "EvilGinx2", Context: "go 1.10.4 linux/amd64", Source: "cedowens/C2-JARM"},
	},
	"07d19d12d21d21d07c07d19d07d21da5a8ab90bcc6bf8bbc6fbec4bcaa8219": {
		{Framework: "Get2", Context: "N/A", Source: "cedowens/C2-JARM"},
	},
	"21d14d00000000021c21d14d21d21d1ee8ae98bf3ef941e91529a93ac62b8b": {
		{Framework: "Covenant", Context: "ASP.NET Core", Source: "cedowens/C2-JARM"},
	},
}
