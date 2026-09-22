# ASTRA Voyager

Extracts candidate IOCs (IPs, domains, URLs) from malware samples ASTRA has
analyzed, feeding the [Feed](https://astra-labs.co/feed.html) page on the
ASTRA site. Originally the project explored hunting C2 infrastructure
directly (Shodan-based discovery + Tor-based fingerprinting) — that code is
still here and working, but the primary focus is now sample-driven: pull
IOCs out of the binaries behind ASTRA's own write-ups, rather than trying to
discover infrastructure nobody's analyzed yet.

## Status

- **`extract`** — the main tool. Pulls candidate network IOCs out of a
  sample's strings (ASCII and UTF-16LE), classifies IPs, and outputs
  ready-to-paste markdown matching ASTRA's write-up format.
- **`discover` / `scan`** — from the earlier C2-infrastructure-hunting
  exploration. `discover` finds candidate hosts via Shodan's `product`/`tag`
  classifications or JARM hashes; `scan` fingerprints one known host
  through Tor. Both still work, kept as a secondary capability rather than
  the project's main direction. See [C2 discovery/scanning](#c2-discoveryscanning-secondary)
  below.

Not built yet: per-family malware config parsers (structured extraction
beyond raw strings — see [How malware analysts do this
elsewhere](#how-other-people-do-this)), aggregation of write-ups' IOC
sections into the actual MISP feed, and a YARA rule library on the site.

## extract — pull IOCs out of a sample

```bash
go run ./cmd/voyager extract <sample-path>
```

```
Usage: voyager extract [flags] <sample-path>

  -format string
        output format: text, markdown, json (default "text")
  -min-len int
        minimum string length to consider (default 5)
```

Example:

```bash
$ go run ./cmd/voyager extract -format markdown suspicious.exe
## Indicators of Compromise

- update-server.evil-actor[.]top
- http[:]//malicious-c2-panel[.]top/gate.php
- 198[.]51[.]100[.]23
```

The `markdown` format defangs output the same way ASTRA's existing
write-ups do (see `malware/acelauncher.txt`): `://` becomes `[:]//`, and
only the last dot in a host — the one separating domain from TLD — gets
bracketed, not every dot.

**These are candidates, not confirmed indicators.** Extracting strings from
a binary pulls in real noise — library URLs, XML namespaces, version
strings that happen to look like a domain. Domain matches are filtered
against a common-TLD allowlist to cut the most obvious noise, but review
the output before pasting it into a write-up. Only ever run this against
samples in an isolated analysis environment.

### Why UTF-16LE matters

Plain `strings` (and naive ASCII-only extraction) misses wide-character
strings entirely. Windows binaries — loaders and droppers especially —
frequently store strings, including C2 URLs, as UTF-16LE. `extract` scans
for both.

## How other people do this

For IOCs sitting in a plainly-readable string, `extract` is enough. Many
malware families instead encrypt or obfuscate their C2 config, which needs
a per-family parser to recover. Worth reusing rather than reinventing when
that's needed:

- [CAPE sandbox](https://github.com/kevoreilly/CAPEv2) — per-family config
  parsers as part of a full detonation sandbox
- [malduck](https://github.com/CERT-Polska/malduck) — CERT.pl's
  config-extraction library, usable standalone
- [MalConfScan](https://github.com/JPCERTCC/MalConfScan) — JPCERT/CC's
  Volatility plugin for memory-resident config extraction

Other approaches to a malware-intel feed worth knowing about, roughly in
order of fit for a single analyst:

1. **Config extraction from samples you analyze** (what `extract` does)
2. **Sandbox detonation** for live network IOCs when a config parser isn't
   worth writing
3. **YARA hunting** (VirusTotal Intelligence retrohunt, MalwareBazaar) to
   find new samples of a tracked family at scale
4. **Honeypots** (Cowrie, T-Pot) for genuinely original data — real
   attacker IPs and dropped samples from traffic hitting your own
   infrastructure
5. **Aggregating existing free feeds** (abuse.ch's MalwareBazaar/URLhaus/ThreatFox)
   with your own context/scoring added — needs clear attribution, not
   presented as original discovery
6. **Certificate transparency / newly-registered-domain monitoring** for
   catching infrastructure before it's used

## C2 discovery/scanning (secondary)

Requires a local Tor daemon for `scan` (`brew install tor && tor`, or
`brew services start tor` to run it persistently) and a Shodan API key for
`discover`. A bare free-signup Shodan key can't use search filters at all —
`ssl.jarm:`, `product:`, `tag:`, etc. all require at least the one-time $49
"Membership" tier.

```bash
export SHODAN_API_KEY=your-key-here

# Shodan's own crawler-side classification — much lower noise than JARM alone
go run ./cmd/voyager discover -query 'product:"Cobalt Strike Beacon"'

# by framework name (looks up every known JARM hash for it)
go run ./cmd/voyager discover -framework "Cobalt Strike"

# fingerprint one already-known target directly, through Tor
go run ./cmd/voyager scan <host:port>
```

Full flag reference: `go run ./cmd/voyager discover -h` / `scan -h`.

**Why this queries Shodan instead of scanning the internet itself:**
scanning the full IPv4 space through Tor isn't practical (10-probe JARM
handshakes with multi-second Tor circuit latency, times ~4 billion
addresses), and mass scanning through Tor exit nodes runs against Tor's own
usage norms. Doing your own internet-wide scan the way Shodan/Censys do
requires dedicated, disclosed scanning infrastructure most researchers
don't build themselves — so `discover` searches infrastructure someone else
already indexed, legitimately and at scale, instead.

**Why JARM alone isn't enough:** it fingerprints the TLS stack, not the
application — unrelated tools on the same language runtime produce
identical hashes (see
[`internal/fingerprint/jarm_signatures.go`](internal/fingerprint/jarm_signatures.go)
for documented collisions). In practice, a real JARM query against
Shodan returned thousands of hits dominated by ordinary mail servers.
Shodan's own `product:`/`tag:` classification (it decodes and labels actual
Cobalt Strike Beacon configs, for example) performed far better. JARM stays
useful as a secondary, corroborating signal.

Signature sources: [salesforce/jarm](https://github.com/salesforce/jarm)
(original research) and [cedowens/C2-JARM](https://github.com/cedowens/C2-JARM)
(broader community hash list). [C2-Tracker](https://github.com/montysecurity/C2-Tracker)
is a maintained project doing Shodan-query-based C2 tracking across more
frameworks, worth referencing for query syntax beyond Cobalt Strike.

## Roadmap

- [ ] Per-family malware config parsers (structured extraction beyond raw strings)
- [ ] Aggregate write-ups' `## Indicators of Compromise` sections into a
      published MISP feed + YARA rule library on the site
- [ ] Additional C2 fingerprint modules: favicon hashing, TLS cert/JA3S defaults
- [ ] Censys as a second Discoverer; automated discover → scan verify step
- [ ] Confidence scoring across multiple independent signals

## Part of the ASTRA Labs Ecosystem

- [Astra AV Engine](https://github.com/ASTRA-LabsHQ/Astra-AV-Engine) — Open-source AV engine built in Go
- [YouTube](https://www.youtube.com/@Astra-Labs) — Malware analysis, reverse engineering, and threat intelligence
- [Discord](https://discord.gg/QPqgBDGthS) — Join the community

## Disclaimer

Voyager is a defensive research tool. Malware samples should only ever be
handled in an isolated analysis environment. C2 probing (`scan`/`discover`)
is intentionally passive/non-intrusive — no exploitation, authentication
attempts, or interaction beyond what's needed to fingerprint a listener.
Use within the scope of authorized research. ASTRA Labs is not responsible
for misuse of this tool.
