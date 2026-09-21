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

Not built yet: additional fingerprint modules (favicon hashing, TLS
cert/JA3S), enrichment integrations (urlscan, GreyNoise, etc.), confidence
scoring across multiple signals, and the MISP feed output. See
[Roadmap](#roadmap).

## Usage

Requires a local Tor daemon (`brew install tor && tor` on macOS, or
`brew services start tor` to run it persistently).

```bash
go run ./cmd/voyager <host:port>
```

```
Usage: voyager [flags] <host:port>

Fingerprints a target for known C2 framework TLS listeners.

  -no-tor
        dial the target directly instead of through Tor (lab/testing use only)
  -timeout duration
        per-probe network timeout (default 5s)
  -tor-addr string
        address of the local Tor SOCKS5 proxy (default "127.0.0.1:9050")
```

Example:

```bash
$ go run ./cmd/voyager 45.33.32.156:443
[*] running jarm against 45.33.32.156:443
    MATCH  framework="Cobalt Strike" indicator=JARM value=07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
           source=cedowens/C2-JARM
           note=JARM fingerprints the TLS stack, not the application — corroborate before treating this as confirmed C2.
```

A "no known-C2 match" result still prints the raw computed fingerprint, so it
can be logged or cross-referenced manually even without a hit.

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
