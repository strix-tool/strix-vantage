# Security Policy — Strix Vantage

## Reporting a vulnerability

Report privately via GitHub Security Advisories (the repo's **Security** tab) or the
[Strix Advanced Tools](https://github.com/strix-tool) maintainer contacts — not a public
issue.

## Authorized use

Vantage is an offensive-recon **orchestrator**. Use it only against systems you own or
are explicitly authorized to test. This document is about the security of **the tool
itself** (so running it can't compromise your own machine), not the scans it performs.

## Threat model & hardening

Vantage runs external tools and, under `sudo`, does so as root. That makes two things
matter: it must not let a target inject commands, and it must not become a way for a
local user or a compromised upstream to run code as root.

- **No shell / no injection.** Every external command uses an argument list
  (`subprocess.run([...])` / `Popen([...])`) — never `shell=True`, `os.system`, or
  `os.popen`. A crafted target such as `localhost; rm -rf ~` is passed as a single argv
  element and is inert. No `eval`/`exec`/`pickle`; the only deserialization is `json.load`
  on a tool's own output. Temp files use `mkstemp`-backed APIs (random names, mode 0600).

- **Auto-install is opt-in and guarded.** Installing missing tools from the internet
  (apt/go/pip/npm) is a supply-chain surface, especially as root. Vantage now:
  prints a warning listing exactly what will be fetched; **requires confirmation when
  running interactively as root**; runs `npm install` with **`--ignore-scripts`** (so a
  package's install hooks cannot execute as root); and honors **`--no-install`** to skip
  entirely. Prefer installing tools yourself from signed distro packages.

- **PATH-hijack guard.** When running as root, directories that are not root-owned or are
  group/world-writable (e.g. an unprivileged user's `~/go/bin`) are **refused** from
  `PATH`, so a planted binary can't be executed as root. The safe failure mode is that
  such a tool simply isn't auto-resolved.

- **Bounded secret scan.** The built-in source/secret scan fetches target HTML/JS. It now
  **caps the number of fetches** (a hostile page can't trigger thousands of 2 MB
  downloads) and uses a **non-backtracking email regex** (no quadratic ReDoS on a crafted
  blob). All network calls have timeouts and a 2 MB size cap.

- **Sanitized output filename.** The default `recon_<target>_<time>.txt` name strips the
  target to filename-safe characters, so a weird target can't steer the path.

## Known limitations

- Auto-installed tool versions are not cryptographically pinned; the confirmation + npm
  `--ignore-scripts` + PATH guard reduce but do not eliminate supply-chain risk. For the
  strongest posture, run with `--no-install` and install every tool yourself from trusted
  packages.
- The TUI's *extra-flags* box and `VANTAGE_PATH` are trusted operator inputs by design
  (they can pass any flag / choose the script) — treat them as such.
- Overwrite-style scanning inherently depends on the upstream tools' own behavior and
  licenses.
