# ASTRA Voyager

Extract and analyze IP addresses from malware samples.

## Features

IP Extraction — Parses raw binary strings output and extracts all embedded IPv4 and IPv6 addresses
IP Classification — Automatically flags private, loopback, and public addresses
Deduplication — Cleans and deduplicates results so you get a clean IOC list
Export — Copy results to clipboard or export as CSV for use in your reports or SIEM
No dependencies — Runs entirely in the browser; your samples never leave your machine


## Usage

Run strings against your malware sample and paste the output, or drop the binary directly
Voyager extracts and categorizes all IP addresses found
Review, filter, and export your IOCs

bash# Quick strings dump to feed into Voyager
strings malware_sample.exe > strings_output.txt

## IP Classification
CategoryExampleDescription🌐 Public185.220.101.45Routable internet address — likely C2 or exfil target🏠 Private192.168.1.1RFC1918 — lateral movement or internal recon🔁 Loopback127.0.0.1Localhost — usually benign📡 Other0.0.0.0, 255.255.255.255Broadcast, unspecified — typically filtered

## Roadmap

 VirusTotal enrichment for extracted IPs
 AbuseIPDB reputation scoring
 Shodan integration for open port/banner data
 CIDR range detection
 PCAP support
 Bulk sample processing


Part of the ASTRA Labs Ecosystem
Voyager is one tool in the ASTRA Labs open-source security toolkit. Check out the rest of the project:

Astra AV Engine — Open-source AV engine built in Go
YouTube — Malware analysis, reverse engineering, and ICS/OT security
Discord — Join the community


Disclaimer
Voyager is intended for use on malware samples you are authorized to analyze, in controlled lab environments. Always conduct malware analysis in an isolated VM. ASTRA Labs is not responsible for misuse of this tool.
