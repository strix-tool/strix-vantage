# Changelog

All notable changes to Strix Vantage are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-07-08

Initial public release — a recon-automation pipeline for authorized web targets.

### Added
- **End-to-end pipeline** — subdomain enumeration, DNS resolution, HTTP probing,
  port scanning (nmap / naabu), technology fingerprinting, content discovery
  (gobuster / ffuf), crawling (katana / hakrawler), TLS inspection, WAF detection,
  vulnerability scanning (nuclei / nikto), and optional heavy DAST
  (sqlmap / dalfox / nuclei-dast / wapiti) behind explicit flags.
- **Profiles** — `recon`, `fast`, `stealth` and `thorough` preset flag bundles.
- **Optional auto-install** of missing tools (opt out with `--no-install`).
- **Consolidated `.txt` report** with a secret scan over collected output.

### Security
- **Authorized-use consent gate** — a one-time typed acknowledgement before the
  first active scan (skippable in automation with `--i-am-authorized`).
- **No shell** — every tool runs via an argv list; the entered target and every
  host from untrusted subdomain enumeration are re-validated before use.
- **Stealth / WAF-safe** controls — request-rate limits, delay/jitter, and tools'
  own evasion modes; **key-less** operation (no secrets committed).
- **Bounded** hostname/secret regexes and per-fetch size caps; `npm` auto-install
  runs with `--ignore-scripts` and a root PATH-hijack guard.

[1.0.0]: https://github.com/strix-tool/strix-vantage/releases/tag/v1.0.0
