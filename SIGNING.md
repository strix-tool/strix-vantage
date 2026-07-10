# Signing & release integrity — Strix Advanced Tools

This document explains how Strix release artifacts are made verifiable today, and
how to turn on code signing later. It applies to all repositories in the
`strix-tool` organization.

## TL;DR — what ships today

Every tagged release (`git tag v1.0.0 && git push --tags`) runs `release.yml`, which:

1. builds the Windows artifact **and** the Linux `.deb`,
2. writes a single **`SHA256SUMS`** covering *every* artifact (Windows + Linux),
3. attaches a **GitHub build-provenance attestation** (SLSA Build Level 2) to each
   artifact, and
4. publishes them all to the GitHub Release.

Builds are **not yet code-signed with a paid certificate**. That is disclosed
plainly on the website's `/security` page. Integrity and origin are proven by the
checksum + attestation instead:

```
# integrity (any user)
Get-FileHash .\Strix-Inspector-Setup.exe -Algorithm SHA256    # Windows
sha256sum -c SHA256SUMS                                        # Linux

# provenance (needs GitHub CLI 2.49+)
gh attestation verify Strix-Inspector-Setup.exe --repo strix-tool/strix-inspector
```

## Why unsigned, for now

- We're a small, independent, zero-budget project. An OV certificate is ~€69–€219/yr.
- Since **March 2024**, even an **EV** certificate no longer instantly clears the
  Windows SmartScreen "unknown publisher" prompt — reputation now builds organically
  from download volume regardless of certificate class. So paying purely to remove the
  warning is no longer worth it.
- **Azure Trusted / Artifact Signing** ($9.99/mo, no token) is the cheapest cloud path
  but is **geo-restricted to US/CA/EU/UK** — a Turkey-based maker is currently ineligible.
  Revisit if eligibility expands.

Unsigned PyInstaller `.exe` files also draw a handful of antivirus **false positives**
(bootloader/packer heuristics + low reputation). Signing meaningfully reduces these,
which is the strongest reason to sign once it's free.

## Recommended path: SignPath Foundation (free for OSS)

[SignPath Foundation](https://signpath.org/) issues a genuinely free, publicly-trusted
**OV code-signing certificate** to qualifying open-source projects. The private key
lives on SignPath's HSM (you never handle it); signing is automated from CI.

- **Trade-off:** the SmartScreen/UAC publisher name shows as **"SignPath Foundation"**,
  not your own name. It still removes the "Unknown publisher" red text and sharply cuts
  antivirus false positives, at $0.
- **Eligibility** needs a public repo, a recognized OSS license (we use MIT), and an
  **existing release** — so **apply after the first `v*` release is tagged**, not before.

### Enabling it (one-time, per repo)

1. Tag and publish the first release so the project qualifies.
2. Apply at <https://signpath.org/apply> and get the project set up in the SignPath UI:
   create a **project** (slug should match the repo, e.g. `strix-talon`), a
   **signing policy** (`release-signing`), and an **artifact configuration** (`exe`).
3. In the GitHub repo, add:
   - repo **variable** `SIGNPATH_ENABLED = true`
   - repo **variable** `SIGNPATH_ORG_ID = <your SignPath organization id>`
   - repo **secret** `SIGNPATH_API_TOKEN = <a SignPath CI user token>`
4. In `release.yml`, **uncomment** the `Sign installer (SignPath)` step in the
   `windows` job (it's already stubbed with the right `project-slug`). It signs the
   `.exe` before it's uploaded, so the checksum + attestation then cover the *signed*
   bytes.
5. For **Sentinel** (shipped as a portable ZIP): sign the `.exe` *before*
   `Compress-Archive`, not the zip.
6. **Linux/script repos** (Vantage, Archer) don't get a Windows signature — checksums +
   attestation are the whole story there; don't imply otherwise.

Per-repo `project-slug` values already stubbed in each `release.yml`:

| Repo | project-slug | Windows asset |
|------|--------------|---------------|
| strix-metavault | `strix-metavault` | Strix-MetaVault-Setup.exe |
| strix-pulse-monitor | `strix-pulse-monitor` | Strix-Pulse-Monitor-Setup.exe |
| strix-sentinel | `strix-sentinel` | Strix-Sentinel-Windows.zip (sign inner .exe) |
| strix-inspector | `strix-inspector` | Strix-Inspector-Setup.exe |
| strix-disk-cleaner | `strix-disk-cleaner` | Strix-Disk-Cleaner-Setup.exe |
| strix-sinkhole | `strix-sinkhole` | Strix-Sinkhole-Setup.exe |
| strix-talon | `strix-talon` | Strix-Talon-Setup.exe |
| strix-vantage | — | (Linux script only) |
| strix-archer | — | (Linux script only) |

## If you want your OWN name as publisher (paid)

The **Certum "Open Source" code-signing certificate** (~€69 first year incl. smartcard +
USB reader, ~€29/yr renewal) is the cheapest paid path that shows *your* verified name,
and Certum verifies individuals internationally, including Turkey. Same organic-reputation
caveat applies. Recommended only if the "SignPath Foundation" publisher name is undesirable.

## Reputation expectations

Signing (SignPath or Certum) removes "Unknown publisher" and cuts AV false positives
**immediately**, but the SmartScreen "not commonly downloaded" prompt fades only as
install volume grows over days/weeks. Don't promise instant, total warning removal — on
the site we frame signing as *reducing*, not eliminating, first-run friction.

## Hardening follow-ups (optional)

- **Pin actions to commit SHAs.** The workflows currently use version tags (`@v4`,
  `@v2`) for readability. Pinning each `uses:` to a full 40-char commit SHA closes a
  supply-chain hole (a compromised tag can't alter the build that produces your
  provenance). `dependabot.yml` (github-actions, weekly) is already in place to bump
  them once pinned.
- **VirusTotal:** after a release is public, upload each artifact, let reputation build
  1–2 weeks, then link the per-file permalink on `/security` **only** if it sits at 0–2
  detections with no Tier-1 engine flagging it. Never post a "clean scan" screenshot.
- **SBOM:** add `anchore/sbom-action` + `actions/attest-sbom` to attach a signed
  dependency list per release.
- **.NET determinism (Inspector):** set `<Deterministic>true</Deterministic>` and
  `<ContinuousIntegrationBuild>true</ContinuousIntegrationBuild>` for reproducible assemblies.
