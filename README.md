# ASTRA Voyager

A C2 infrastructure hunter. Voyager fingerprints suspected command-and-control
listeners on the internet using network-level artifacts (TLS fingerprints,
banners, favicons, and more as modules are added), enriches confirmed
infrastructure with free OSINT sources, and publishes the results as an
intelligence feed.

Probing goes through Tor by default, so contact with adversary infrastructure
isn't tied back to the research machine's own IP.

## Status

Early and under active development. What exists right now:

- **Tor transport** — dials targets through a local Tor SOCKS5 proxy
- **JARM fingerprinting** — active TLS fingerprinting, checked against a
  sourced database of known C2/red-team framework hashes (Cobalt Strike,
  Metasploit, Sliver, Mythic, Merlin, Covenant, and more)
- **Discovery via Shodan** — finds *new* candidate hosts by searching Shodan
  for known fingerprints, rather than scanning the internet directly (see
  [How discovery works](#how-discovery-works) for why)
- **Scan** — fingerprints one already-known `host:port` directly, through Tor

Not built yet: additional fingerprint modules (favicon hashing, TLS
cert/JA3S), a Censys discoverer, enrichment integrations (urlscan, GreyNoise,
etc.), confidence scoring across multiple signals, and the MISP feed output.
See [Roadmap](#roadmap).

## Usage

Requires a local Tor daemon for `scan` (`brew install tor && tor` on macOS,
or `brew services start tor` to run it persistently) and a Shodan API key
for `discover`.

**Shodan tier matters:** a bare free-signup API key can't use search filters
at all (`ssl.jarm:`, `http.favicon.hash:`, etc. all require at least the
one-time $49 "Membership" tier — see [Shodan's pricing
page](https://developer.shodan.io/pricing)). `discover` will fail on every
query with a free-tier key.

### discover — find new candidate hosts

```bash
export SHODAN_API_KEY=your-key-here

# by framework name (looks up every known JARM hash for it)
go run ./cmd/voyager discover -framework "Cobalt Strike"

# by a specific JARM hash
go run ./cmd/voyager discover -jarm 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1

# or a raw Shodan query
go run ./cmd/voyager discover -query 'ssl.jarm:"07d14d..." country:US'
```

```
Usage: voyager discover [flags]

  -framework string
        C2 framework name to search for, e.g. "Cobalt Strike"
  -jarm string
        raw JARM hash to search Shodan for
  -query string
        raw Shodan search query, overrides -jarm/-framework
  -limit int
        max candidates to return per query (default 100)
  -shodan-key string
        Shodan API key (default: $SHODAN_API_KEY)
```

Output is a list of unverified `ip:port` candidates — leads, not confirmed
C2. Cross-check with `scan` (or a future automated verify step) before
treating any of them as live.

### scan — fingerprint one known target

```bash
go run ./cmd/voyager scan <host:port>
```

```
Usage: voyager scan [flags] <host:port>

  -no-tor
        dial the target directly instead of through Tor (lab/testing use only)
  -timeout duration
        per-probe network timeout (default 5s)
  -tor-addr string
        address of the local Tor SOCKS5 proxy (default "127.0.0.1:9050")
```

Example:

```bash
$ go run ./cmd/voyager scan 45.33.32.156:443
[*] running jarm against 45.33.32.156:443
    MATCH  framework="Cobalt Strike" indicator=JARM value=07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
           source=cedowens/C2-JARM
           note=JARM fingerprints the TLS stack, not the application — corroborate before treating this as confirmed C2.
```

A "no known-C2 match" result still prints the raw computed fingerprint, so it
can be logged or cross-referenced manually even without a hit.

## How discovery works

Voyager does not, and will not, scan the internet itself. Scanning the full
IPv4 space through Tor isn't practical (10-probe JARM handshakes with
multi-second Tor circuit latency, times ~4 billion addresses) and mass
scanning through Tor exit nodes runs against Tor's own usage norms. Doing
your own internet-wide scan the way Shodan/Censys do requires dedicated,
disclosed scanning infrastructure most researchers don't build themselves.

Instead, `discover` queries Shodan — which has already scanned the internet,
legitimately and at scale — for hosts matching a known fingerprint. That
turns "find new C2 infrastructure" into "search infrastructure someone else
already indexed," which is both the practical and the responsible way to do
this.

## How detection works

JARM sends 10 specially-crafted TLS Client Hello probes and hashes the
server's responses — different TLS stacks/libraries answer differently, so
the resulting hash is a strong signal for identifying the *software* behind a
listener, independent of IP or domain reputation.

**Important caveat:** JARM fingerprints the TLS stack, not the specific
application. Multiple unrelated tools built on the same language runtime
(e.g. Python + aiohttp) produce identical hashes — see
[`internal/fingerprint/jarm_signatures.go`](internal/fingerprint/jarm_signatures.go)
for documented collisions. A JARM hit is a candidate worth investigating
further, never a standalone conclusion. This is why Voyager is being built
to combine multiple independent signals before anything is published to the
feed.

Signature sources:
- [salesforce/jarm](https://github.com/salesforce/jarm) — original JARM
  research and reference Cobalt Strike/Metasploit/Merlin hashes
- [cedowens/C2-JARM](https://github.com/cedowens/C2-JARM) — broader
  community-maintained C2/red-team framework hash list

## Roadmap

- [ ] Additional fingerprint modules: favicon hashing (mmh3), TLS
      certificate CN/issuer defaults, HTTP response fingerprints
- [ ] Censys as a second Discoverer
- [ ] Automated verify step: pipe `discover` candidates straight into `scan`
- [ ] Confidence scoring across multiple independent signals
- [ ] Enrichment: urlscan.io, Shodan InternetDB, abuse.ch (ThreatFox/URLhaus),
      crt.sh, GreyNoise Community API, RDAP/WHOIS
- [ ] MISP feed output (manifest + per-event JSON), hosted as a static feed
- [ ] Infrastructure clustering (ASN/cert/JARM reuse across IPs)
- [ ] Passive DNS integration
- [ ] Scheduled re-verification with `first_seen`/`last_seen` tracking

## Part of the ASTRA Labs Ecosystem

- [Astra AV Engine](https://github.com/ASTRA-LabsHQ/Astra-AV-Engine) — Open-source AV engine built in Go
- [YouTube](https://www.youtube.com/@Astra-Labs) — Malware analysis, reverse engineering, and threat intelligence
- [Discord](https://discord.gg/QPqgBDGthS) — Join the community

## Disclaimer

Voyager is a defensive research tool for identifying and tracking malicious
infrastructure. Probing is intentionally passive/non-intrusive (TLS
handshakes, banner/favicon fetches) — no exploitation, authentication
attempts, or interaction beyond what's needed to fingerprint a listener. Use
it within the scope of authorized research. ASTRA Labs is not responsible
for misuse of this tool.
