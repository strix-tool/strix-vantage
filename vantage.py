#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vantage
-------
Recon automation pipeline for authorized targets (e.g. a local intentionally-vulnerable practice app).

Flow:
    subfinder + sublist3r + amass          ->  unique subdomain list
    httpx                                  ->  active (live) targets
    for each live target:
        whatweb                            ->  technology fingerprint
        naabu -> nmap                      ->  open ports + service/version
        nuclei                             ->  vulnerability templates
        nikto                              ->  web server checks
        gobuster                           ->  content discovery (200 only)
        katana + hakrawler                 ->  crawled URLs / endpoints
        secret scan                        ->  emails / creds / tokens in source
    result                                 ->  a neatly formatted .txt report

All active steps run in quiet / low-impact mode so a local server is not stressed.

NOTE: Use Vantage ONLY against systems you own or are authorized to test.
A local intentionally-vulnerable practice app is ideal for exactly this purpose.
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error
from datetime import datetime
from urllib.parse import urlparse, urljoin

# ----------------------------------------------------------------------
# Settings (tweak here if needed)
# ----------------------------------------------------------------------
GOBUSTER_WORDLIST = "/usr/share/wordlists/dirb/big.txt"

NMAP_EXTRA_ARGS   = ["-sV", "-T2"]
NMAP_SYN_SCAN     = "-sS"

NUCLEI_RATE_LIMIT  = "10"
NUCLEI_CONCURRENCY = "5"
NUCLEI_BULK_SIZE   = "5"

GOBUSTER_THREADS   = "10"
GOBUSTER_DELAY     = ""

AMASS_TIMEOUT      = "5"

NAABU_RATE         = "150"

KATANA_RATE_LIMIT  = "10"
KATANA_DEPTH       = "2"
KATANA_CONCURRENCY = "5"

HAKRAWLER_DEPTH    = "2"
HAKRAWLER_THREADS  = "3"

WHATWEB_AGGRESSION = "1"

NIKTO_PAUSE        = "1"
NIKTO_MAXTIME      = "300"

# ffuf (content discovery) - gentle/WAF-safe: low rate + threads. -ffuf-fs lets
# you filter the SPA's default response size.
FFUF_RATE          = "20"    # requests/sec (0 = unlimited; keep low)
FFUF_THREADS       = "10"

# sqlmap (opt-in) - gentle: level 1 / risk 1, capped number of URLs
SQLMAP_LEVEL       = "1"
SQLMAP_RISK        = "1"
SQLMAP_MAX_URLS    = 5       # test at most this many parameterized URLs

# --stealth: WAF/IDS-evasion tuning (low rate + inter-request delay/jitter +
# tools' own WAF-evasion modes). Reduces rate-based blocking; payload-signature
# blocking can't be fully avoided since DAST must send payloads.
STEALTH_NUCLEI_RATE      = "3"
STEALTH_NUCLEI_CONC      = "10"
STEALTH_FFUF_RATE        = "5"
STEALTH_FFUF_DELAY       = "0.3-0.9"   # ffuf -p (jitter, seconds)
STEALTH_GOBUSTER_THREADS = "3"
STEALTH_GOBUSTER_DELAY   = "400ms"
STEALTH_NAABU_RATE       = "50"
STEALTH_DALFOX_DELAY     = "800"       # ms between requests to same host
STEALTH_DALFOX_WORKER    = "1"

CMD_TIMEOUT        = 1800

HTTPX_BIN = "httpx"

REQUIRED_TOOLS = ["subfinder", "sublist3r", "amass", "dnsx", "naabu", "nmap",
                  "nuclei", "nikto", "whatweb", "wafw00f", "gobuster", "ffuf",
                  "tlsx", "katana", "hakrawler", "arjun", "retire"]

# ----------------------------------------------------------------------
# Auto-install recipes for missing tools (apt -> go install -> pip -> npm).
# ----------------------------------------------------------------------
INSTALL_APT = {
    "subfinder": "subfinder", "sublist3r": "sublist3r", "amass": "amass",
    "dnsx": "dnsx", "naabu": "naabu", "nmap": "nmap", "nuclei": "nuclei",
    "nikto": "nikto", "whatweb": "whatweb", "wafw00f": "wafw00f",
    "gobuster": "gobuster", "ffuf": "ffuf", "sslscan": "sslscan",
    "sqlmap": "sqlmap", "katana": "katana", "httpx": "httpx-toolkit",
    "arjun": "arjun", "dalfox": "dalfox", "wapiti": "wapiti",
}
INSTALL_GO = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "amass": "github.com/owasp-amass/amass/v4/...@master",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "gobuster": "github.com/OJ/gobuster/v3@latest",
    "ffuf": "github.com/ffuf/ffuf/v2@latest",
    "tlsx": "github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "hakrawler": "github.com/hakluke/hakrawler@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "dalfox": "github.com/hahwul/dalfox/v2@latest",
}
INSTALL_PIP = {
    "sublist3r": "sublist3r", "wafw00f": "wafw00f", "sqlmap": "sqlmap",
    "arjun": "arjun", "wapiti": "wapiti3",
}
INSTALL_NPM = {
    "retire": "retire",
}

# ----------------------------------------------------------------------
# Profiles: named presets that turn on a bundle of flags (additive - any
# extra flag you pass is still applied on top).
# ----------------------------------------------------------------------
PROFILES = {
    # discovery + fingerprint only, no active vulnerability scanning
    "recon":    {"skip_nuclei": True, "skip_nikto": True,
                 "skip_gobuster": True, "skip_ffuf": True},
    # quick standard pass (fewer templates, skip the slow nikto)
    "fast":     {"fast": True, "nuclei_auto": True, "skip_nikto": True},
    # WAF-evasive everyday scan
    "stealth":  {"katana_headless": True, "fast": True, "stealth": True},
    # maximum coverage, WAF-evasive
    "thorough": {"katana_headless": True, "force": True,
                 "stealth": True, "sqlmap": True},
}

# ----------------------------------------------------------------------
# Branding + terminal UI (colors, live status, banner)
# ----------------------------------------------------------------------
VERSION = "2.2"

BANNER = r"""
 ██╗   ██╗ █████╗ ███╗   ██╗████████╗ █████╗  ██████╗ ███████╗
 ██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔════╝ ██╔════╝
 ██║   ██║███████║██╔██╗ ██║   ██║   ███████║██║  ███╗█████╗  
 ╚██╗ ██╔╝██╔══██║██║╚██╗██║   ██║   ██╔══██║██║   ██║██╔══╝  
  ╚████╔╝ ██║  ██║██║ ╚████║   ██║   ██║  ██║╚██████╔╝███████╗
   ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
"""

TAGLINE = "  recon automation pipeline  ·  v%s" % VERSION


class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"
    GRAY = "\033[90m"; WHITE = "\033[97m"


USE_COLOR = True
DEBUG = False
STEALTH = False


def _c(text, color):
    return f"{color}{text}{C.RESET}" if USE_COLOR else text


def _ts():
    return datetime.now().strftime("%H:%M:%S")


def print_banner():
    print(_c(BANNER, C.CYAN + C.BOLD))
    print(_c(TAGLINE, C.MAGENTA))
    print(_c("  only use against targets you are authorized to test", C.GRAY) + "\n")


def log_phase(msg):
    line = "─" * 62
    print()
    print(_c(line, C.CYAN))
    print(_c("  ▶ " + msg, C.CYAN + C.BOLD))
    print(_c(line, C.CYAN))


def log_target(i, n, url):
    print()
    print(_c(f"  ● target {i}/{n}  ", C.MAGENTA + C.BOLD) + _c(url, C.WHITE + C.BOLD))


def log_step(msg):
    print(_c(f"  [{_ts()}] ", C.GRAY) + _c("→ ", C.BLUE) + msg)


def log_result(label, detail):
    print(_c(f"  [{_ts()}] ", C.GRAY) + _c("✔ ", C.GREEN)
          + _c(label, C.BOLD) + _c(" · ", C.GRAY) + _c(detail, C.WHITE))


def log_warn(msg):
    print(_c(f"  [{_ts()}] ", C.GRAY) + _c("! ", C.YELLOW) + _c(msg, C.YELLOW))


def log_info(msg):
    print(_c(f"  [{_ts()}] ", C.GRAY) + _c("· ", C.GRAY) + msg)


def log_debug(msg):
    if DEBUG:
        print(_c(f"  [{_ts()}] ", C.GRAY) + _c("dbg ", C.GRAY) + _c(msg, C.GRAY))


def first_line(text, n=80):
    for l in text.splitlines():
        if l.strip():
            return l.strip()[:n]
    return "-"


def _num(text, pat):
    m = re.search(pat, text)
    return int(m.group(1)) if m else 0


class VantageParser(argparse.ArgumentParser):
    def format_help(self):
        return BANNER + "\n" + TAGLINE + "\n\n" + super().format_help()


# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def run_cmd(cmd, timeout=CMD_TIMEOUT, input_text=None):
    """Run a command; return (rc, stdout, stderr). Never raises on failure."""
    log_debug("run: " + " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout ({timeout}s): {' '.join(cmd)}"
    except Exception as e:
        return 1, "", f"Error: {e}"


def check_tools(httpx_bin):
    """Return the list of tools not found in PATH."""
    missing = []
    for t in REQUIRED_TOOLS + [httpx_bin]:
        if shutil.which(t) is None:
            missing.append(t)
    return missing


def _root_safe_dir(d):
    """True if dir `d` is safe to add to root's PATH: it exists, is root-owned,
    and is NOT group/other-writable. Prevents a user-writable dir (e.g. an
    unprivileged user's ~/go/bin) from being used to plant a binary that root
    would then execute."""
    try:
        st = os.stat(d)
    except OSError:
        return False
    return st.st_uid == 0 and not (st.st_mode & 0o022)


def ensure_go_bin_on_path():
    """Add common Go bin dirs to PATH so freshly `go install`-ed tools resolve.
    When running as root, user-writable candidate dirs are refused (PATH-hijack
    guard); the safe failure mode is simply not auto-resolving such tools."""
    candidates = []
    if os.environ.get("GOBIN"):
        candidates.append(os.environ["GOBIN"])
    if os.environ.get("GOPATH"):
        candidates.append(os.path.join(os.environ["GOPATH"], "bin"))
    candidates.append(os.path.join(os.path.expanduser("~"), "go", "bin"))
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        candidates.append(f"/home/{sudo_user}/go/bin")
    is_root = getattr(os, "geteuid", lambda: 1)() == 0
    parts = os.environ.get("PATH", "").split(os.pathsep)
    for c in candidates:
        if not c or not os.path.isdir(c) or c in parts:
            continue
        if is_root and not _root_safe_dir(c):
            continue
        os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + c
        parts.append(c)


def try_install(tool, is_root):
    """Try to install one missing tool: apt -> go install -> pip. Returns bool."""
    sudo = [] if is_root else ["sudo"]
    pkg = INSTALL_APT.get(tool)
    if pkg and shutil.which("apt-get"):
        log_info(f"{tool}: trying 'apt-get install {pkg}'")
        run_cmd(sudo + ["apt-get", "install", "-y", pkg], timeout=600)
        if shutil.which(tool):
            return True
    mod = INSTALL_GO.get(tool)
    if mod and shutil.which("go"):
        log_info(f"{tool}: trying 'go install {mod}'")
        run_cmd(["go", "install", "-v", mod], timeout=900)
        ensure_go_bin_on_path()
        if shutil.which(tool):
            return True
    ppkg = INSTALL_PIP.get(tool)
    if ppkg and shutil.which("pip"):
        log_info(f"{tool}: trying 'pip install {ppkg}'")
        run_cmd(["pip", "install", "--break-system-packages", ppkg], timeout=600)
        if shutil.which(tool):
            return True
    npkg = INSTALL_NPM.get(tool)
    if npkg and shutil.which("npm"):
        log_info(f"{tool}: trying 'npm install -g --ignore-scripts {npkg}'")
        # --ignore-scripts: never run an npm package's (pre|post)install hooks,
        # which would otherwise execute as root and are a supply-chain RCE path.
        run_cmd(sudo + ["npm", "install", "-g", "--ignore-scripts", npkg], timeout=600)
        if shutil.which(tool):
            return True
    return False


def auto_install(missing, is_root):
    """Attempt to install every missing tool. Returns the still-missing list."""
    # Security notice: auto-install fetches third-party code from the internet
    # (apt/go/pip/npm). Under sudo, apt runs as root. These sources are not
    # version-pinned, so a compromised upstream is a supply-chain risk. Prefer
    # installing tools yourself from trusted distro packages and using
    # --no-install. When root and interactive, require explicit confirmation.
    log_warn("Auto-install will fetch these tools from the internet (apt/go/pip/npm): "
             + ", ".join(missing))
    log_warn("Sources are not pinned. Safer: install them from your distro's "
             "packages and run with --no-install.")
    if is_root and sys.stdin.isatty():
        try:
            ans = input("Proceed with auto-install as root? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans not in ("y", "yes"):
            log_info("Auto-install declined; continuing with the tools already present.")
            return list(missing)
    ensure_go_bin_on_path()
    if shutil.which("apt-get") and any(t in INSTALL_APT for t in missing):
        sudo = [] if is_root else ["sudo"]
        log_info("apt-get update")
        run_cmd(sudo + ["apt-get", "update"], timeout=600)
    still_missing = []
    for t in missing:
        if try_install(t, is_root):
            log_result(t, "installed")
        else:
            still_missing.append(t)
    return still_missing


def _nuclei_templates_present():
    home = os.path.expanduser("~")
    for p in (os.path.join(home, "nuclei-templates"),
              os.path.join(home, ".local", "nuclei-templates")):
        try:
            if os.path.isdir(p) and os.listdir(p):
                return True
        except OSError:
            pass
    return False


def ensure_nuclei_templates(force=False):
    """Make sure nuclei has templates in THIS user's home (root under sudo has
    its own home, so templates from your normal user are not visible)."""
    if shutil.which("nuclei") is None:
        return
    if force or not _nuclei_templates_present():
        log_step("nuclei -update-templates (first run / missing templates)")
        _, _, err = run_cmd(["nuclei", "-update-templates", "-silent"], timeout=600)
        if _nuclei_templates_present():
            log_result("nuclei templates", "ready")
        else:
            log_warn("nuclei templates still not found "
                     + ((err.strip().splitlines()[-1][:160]) if err.strip() else ""))


def normalize_target(raw):
    """Return (bare_domain, probe_target) from a domain/URL/host:port string."""
    raw = raw.strip()
    if "://" in raw:
        parsed = urlparse(raw)
    else:
        parsed = urlparse("http://" + raw)
    bare = parsed.hostname or raw
    return bare, raw


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


def valid_host(host):
    """True if `host` is a syntactically valid hostname or IP literal.

    A scan operand must never begin with '-' (it would be parsed as an option by
    nmap/sslscan/testssl/naabu) or contain shell/space/flag characters. This is
    enforced on both the entered target AND every host coming out of untrusted
    subdomain-enumeration output before it reaches any tool.
    """
    if not host or host[0] == "-":
        return False
    h = host.strip()
    if "://" in h:                       # tolerate a scheme (http://host:port/path)
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]               # drop any path
    if h.startswith("[") and "]" in h:   # [::1]:3000 -> ::1
        h = h[1:h.index("]")]
    elif h.count(":") == 1:              # host:port -> host (single colon only; IPv6 has many)
        h = h.split(":", 1)[0]
    if not h or len(h) > 253 or h[0] == "-":
        return False
    try:
        ipaddress.ip_address(h)          # accepts localhost IPs / v4 / v6
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(h))   # accepts single-label hosts like 'localhost'


def merge_urls(*blobs):
    """Merge multiple newline blobs of URLs into a sorted, deduplicated block."""
    urls = set()
    for b in blobs:
        for ln in b.splitlines():
            ln = ln.strip()
            if ln:
                urls.add(ln)
    if not urls:
        return "(no URLs found)"
    lines = [f"total unique URLs: {len(urls)}", ""]
    lines += sorted(urls)
    return "\n".join(lines)


def pick_primary(live, bare):
    """Return the primary (entered) target among the live URLs: the one whose
    host matches the entered domain, else the first live target."""
    for u in live:
        if (urlparse(u).hostname or "") == bare:
            return u
    return live[0] if live else None


# ----------------------------------------------------------------------
# Subdomain enumeration
# ----------------------------------------------------------------------
def run_subfinder(domain):
    log_step(f"subfinder -> {domain}")
    rc, out, err = run_cmd(["subfinder", "-d", domain, "-silent"])
    subs = {ln.strip() for ln in out.splitlines() if ln.strip()}
    if rc not in (0,) and not subs:
        log_warn(f"subfinder: {err.strip()[:160]}")
    log_result("subfinder", f"{len(subs)} subdomain(s)")
    return subs


def run_sublist3r(domain):
    log_step(f"sublist3r -> {domain}")
    tmp = tempfile.NamedTemporaryFile(mode="r", suffix=".txt", delete=False)
    tmp.close()
    _, _, _ = run_cmd(["sublist3r", "-d", domain, "-o", tmp.name])
    subs = set()
    try:
        with open(tmp.name, "r", errors="ignore") as f:
            subs = {ln.strip() for ln in f if ln.strip()}
    except OSError:
        pass
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    log_result("sublist3r", f"{len(subs)} subdomain(s)")
    return subs


def run_amass(domain):
    log_step(f"amass (passive) -> {domain}")
    tmp = tempfile.NamedTemporaryFile(mode="r", suffix=".txt", delete=False)
    tmp.close()
    cmd = ["amass", "enum", "-passive", "-d", domain,
           "-timeout", AMASS_TIMEOUT, "-o", tmp.name]
    _, _, _ = run_cmd(cmd)
    subs = set()
    try:
        with open(tmp.name, "r", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if ln:
                    subs.add(ln.split()[0])
    except OSError:
        pass
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    log_result("amass", f"{len(subs)} subdomain(s)")
    return subs


# ----------------------------------------------------------------------
# Liveness
# ----------------------------------------------------------------------
def _http_alive(url, timeout=8):
    """True if the URL returns any HTTP response (even 4xx/5xx) = host is up."""
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "vantage"})
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except urllib.error.HTTPError:
        return True   # got an HTTP status back -> alive
    except Exception:
        return False


def stdlib_liveness(targets):
    """Built-in liveness fallback used when a proper httpx is unavailable."""
    live = []
    for t in targets:
        cands = [t] if "://" in t else [f"http://{t}", f"https://{t}"]
        for u in cands:
            if _http_alive(u):
                live.append(u)
                break
    return live


def resolve_httpx(preferred):
    """
    Return the first binary that is the ProjectDiscovery httpx (supports -l),
    or None. The python3-httpx CLI is NOT usable here (no -l/-silent); it is
    rejected because it exits non-zero on `-version`.
    """
    tried = []
    for cand in [preferred, "httpx-toolkit", "httpx"]:
        if not cand or cand in tried:
            continue
        tried.append(cand)
        if shutil.which(cand) is None:
            continue
        rc, _, _ = run_cmd([cand, "-version"], timeout=30)
        if rc == 0:            # PD httpx prints a version and exits 0
            return cand
    return None


def run_httpx(targets, httpx_bin):
    log_step(f"httpx liveness ({len(targets)} target(s))")
    real = resolve_httpx(httpx_bin)
    if real is None:
        log_warn("no ProjectDiscovery httpx (python 'httpx' lacks -l) -> built-in liveness check")
        live = stdlib_liveness(targets)
        log_result("liveness", f"{len(live)} live target(s) (built-in)")
        return live
    if real != httpx_bin:
        log_info(f"using '{real}' as httpx")
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    for t in targets:
        tmp.write(t + "\n")
    tmp.close()
    _, out, err = run_cmd([real, "-l", tmp.name, "-silent"])
    try:
        os.unlink(tmp.name)
    except OSError:
        pass
    live = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if not live:
        if err.strip():
            log_warn(f"httpx: {err.strip()[:160]}")
        recovered = stdlib_liveness(targets)
        if recovered:
            log_info("recovered live targets via built-in check")
            live = recovered
    log_result("httpx", f"{len(live)} live target(s)")
    return live


# ----------------------------------------------------------------------
# Per-host scan steps (all in quiet / low-impact mode)
# ----------------------------------------------------------------------
def run_whatweb(url):
    cmd = ["whatweb", "-a", WHATWEB_AGGRESSION, "--color=never", "--no-errors", url]
    _, out, _ = run_cmd(cmd)
    return out.strip() or "(no output)"


def run_naabu(host, use_syn):
    rate = STEALTH_NAABU_RATE if STEALTH else NAABU_RATE
    cmd = ["naabu", "-host", host, "-silent", "-rate", rate]
    if not use_syn:
        cmd += ["-scan-type", "c"]
    _, out, _ = run_cmd(cmd)
    ports = []
    for ln in out.splitlines():
        ln = ln.strip()
        if ":" in ln:
            p = ln.rsplit(":", 1)[-1]
            if p.isdigit():
                ports.append(p)
    return sorted(set(ports), key=int)


def run_nmap(url, use_syn, ports=None):
    host = urlparse(url).hostname or url
    scan = [NMAP_SYN_SCAN] if use_syn else ["-sT"]
    cmd = ["nmap"] + scan + NMAP_EXTRA_ARGS
    if ports:
        cmd += ["-p", ",".join(ports)]
    cmd += [host]
    _, out, err = run_cmd(cmd)
    return out.strip() or (err.strip() or "(no output)")


def run_nuclei(url, rate=NUCLEI_RATE_LIMIT, concurrency=NUCLEI_CONCURRENCY,
               ni=False, tags="", severity="", auto=False):
    # NOTE: speed comes from running FEWER templates (auto/tags/severity), NOT
    # from a higher rate. A high rate/concurrency would trip an IDS/WAF and get
    # you blocked, so the rate stays low by default.
    cmd = [
        "nuclei", "-u", url, "-silent",
        "-rate-limit", rate,
        "-concurrency", concurrency,
        "-bulk-size", NUCLEI_BULK_SIZE,
    ]
    if ni:
        cmd += ["-no-interactsh"]     # skip OOB templates/polling
    if auto:
        cmd += ["-as"]                # automatic scan: only tech-matched templates
    if tags:
        cmd += ["-tags", tags]
    if severity:
        cmd += ["-severity", severity]
    _, out, err = run_cmd(cmd)
    out = out.strip()
    if out:
        return out
    # No findings on stdout -> surface a hint from stderr so 0 is explainable
    # (e.g. "no templates found", flag errors, permission issues under sudo).
    err = err.strip()
    if err:
        return "(no findings)\nnote: " + err.splitlines()[-1][:200]
    return "(no findings)"


def run_nikto(url):
    cmd = ["nikto", "-h", url,
           "-Pause", NIKTO_PAUSE,
           "-maxtime", NIKTO_MAXTIME,
           "-nointeractive",
           "-ask", "no"]
    _, out, err = run_cmd(cmd)
    return out.strip() or (err.strip() or "(no output)")


def run_gobuster(url, wordlist, threads=GOBUSTER_THREADS):
    if not os.path.isfile(wordlist):
        return f"(wordlist not found: {wordlist})"
    if STEALTH:
        threads = STEALTH_GOBUSTER_THREADS
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist,
           "-t", threads, "-q", "-s", "200", "-b", ""]
    if STEALTH:
        cmd += ["--delay", STEALTH_GOBUSTER_DELAY]
    elif GOBUSTER_DELAY:
        cmd += ["--delay", GOBUSTER_DELAY]
    _, out, _ = run_cmd(cmd)
    return out.strip() or "(no findings)"


def run_katana(url, headless=False):
    cmd = ["katana", "-u", url, "-silent",
           "-rate-limit", KATANA_RATE_LIMIT,
           "-depth", KATANA_DEPTH,
           "-concurrency", KATANA_CONCURRENCY]
    if headless:
        cmd += ["-headless", "-no-sandbox"]
    _, out, _ = run_cmd(cmd)
    return out.strip()


def run_hakrawler(url):
    _, out, _ = run_cmd(["hakrawler", "-d", HAKRAWLER_DEPTH,
                            "-t", HAKRAWLER_THREADS, "-u"],
                           input_text=url + "\n")
    return out.strip()


def run_dnsx(subdomains):
    """Resolve/validate discovered subdomains (drops dead names + wildcards).
    Non-destructive: if dnsx is missing or resolves nothing, keep the originals
    (important for internal/home-lab domains that public resolvers can't see)."""
    subs = set(subdomains)
    if not subs or shutil.which("dnsx") is None:
        return subs
    log_step(f"dnsx - resolving/validating {len(subs)} name(s)")
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    for s in sorted(subs):
        tmp.write(s + "\n")
    tmp.close()
    _, out, _ = run_cmd(["dnsx", "-l", tmp.name, "-silent"])
    try:
        os.unlink(tmp.name)
    except OSError:
        pass
    resolved = {ln.strip() for ln in out.splitlines() if ln.strip()}
    if not resolved:
        log_warn("dnsx resolved 0 (internal DNS?) -> keeping original list")
        return subs
    log_result("dnsx", f"{len(resolved)} resolvable (of {len(subs)})")
    return resolved


def run_wafw00f(url):
    _, out, _ = run_cmd(["wafw00f", url])
    out = out.strip()
    # keep only the informative lines (drop the ascii banner)
    lines = [l for l in out.splitlines()
             if any(k in l for k in ("is behind", "seems to be behind",
                                     "No WAF", "Generic", "detected"))]
    return "\n".join(lines) or (out or "(no output)")


def run_tls(host):
    """TLS/cert/cipher check. Prefer tlsx (fast) -> sslscan -> testssl.sh (slow)."""
    if shutil.which("tlsx"):
        _, out, _ = run_cmd(["tlsx", "-u", host, "-silent",
                                "-cn", "-san", "-cipher", "-tls-version",
                                "-expired", "-self-signed"])
        return out.strip() or "(no TLS data)"
    if shutil.which("sslscan"):
        _, out, _ = run_cmd(["sslscan", "--no-colour", host])
        return out.strip() or "(no output)"
    tbin = "testssl.sh" if shutil.which("testssl.sh") else ("testssl" if shutil.which("testssl") else None)
    if tbin:
        _, out, _ = run_cmd([tbin, "--fast", "--quiet", "--color", "0", host], timeout=600)
        return out.strip() or "(no output)"
    return "(no TLS tool available: tlsx / sslscan / testssl.sh)"


def run_ffuf(url, wordlist, fs=""):
    if shutil.which("ffuf") is None:
        return "(ffuf not installed)"
    if not os.path.isfile(wordlist):
        return f"(wordlist not found: {wordlist})"
    base = url.rstrip("/")
    rate = STEALTH_FFUF_RATE if STEALTH else FFUF_RATE
    cmd = ["ffuf", "-u", base + "/FUZZ", "-w", wordlist,
           "-mc", "200", "-rate", rate, "-t", FFUF_THREADS, "-s"]
    if fs:
        cmd += ["-fs", fs]     # filter the SPA's default response size
    if STEALTH:
        cmd += ["-p", STEALTH_FFUF_DELAY]   # jittered delay between requests
    _, out, _ = run_cmd(cmd)
    return out.strip() or "(no findings)"


def _sqlmap_summary(out):
    keys = ("injectable", "is vulnerable", "back-end DBMS", "Parameter:",
            "might be injectable", "does not seem to be injectable",
            "all tested parameters do not appear")
    lines = [l for l in out.splitlines() if any(k.lower() in l.lower() for k in keys)]
    return "\n".join(lines[-25:]) or "(no clear injection result)"


def run_sqlmap(crawl_output):
    if shutil.which("sqlmap") is None:
        return "(sqlmap not installed)"
    # only URLs that carry query parameters are worth testing
    urls = [ln.strip() for ln in crawl_output.splitlines()
            if "?" in ln and "=" in ln and ln.lower().startswith("http")]
    urls = urls[:SQLMAP_MAX_URLS]
    if not urls:
        return "(no parameterized URLs found to test)"
    blocks = []
    for u in urls:
        log_info(f"sqlmap testing {u}")
        _, out, _ = run_cmd(["sqlmap", "-u", u, "--batch",
                                "--level", SQLMAP_LEVEL, "--risk", SQLMAP_RISK,
                                "--random-agent", "--disable-coloring"],
                               timeout=600)
        blocks.append(f"# {u}\n" + _sqlmap_summary(out))
    return "\n\n".join(blocks)


def _param_urls(crawl_output):
    return [ln.strip() for ln in crawl_output.splitlines()
            if "?" in ln and "=" in ln and ln.strip().lower().startswith("http")]


def run_arjun(url):
    """Discover hidden HTTP parameters. Returns (display_text, [params])."""
    if shutil.which("arjun") is None:
        return "(arjun not installed)", []
    tmp = tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False)
    tmp.close()
    run_cmd(["arjun", "-u", url, "-oJ", tmp.name])
    params = []
    try:
        with open(tmp.name, "r", errors="ignore") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    params += [str(x) for x in v]
                elif isinstance(v, dict):
                    params += [str(x) for x in v.get("params", [])]
    except Exception:
        pass
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    params = sorted(set(params))
    disp = ("found parameters: " + ", ".join(params)) if params else "(no parameters found)"
    return disp, params


def run_retirejs(crawl_output):
    """Download crawled .js files and scan them for known-vulnerable libraries."""
    if shutil.which("retire") is None:
        return "(retire.js not installed - needs 'npm install -g retire')"
    js_urls = [ln.strip() for ln in crawl_output.splitlines()
               if ln.strip().split("?")[0].lower().endswith(".js")]
    if not js_urls:
        return "(no JS files found to scan)"
    tmpdir = tempfile.mkdtemp()
    n = 0
    for u in js_urls[:50]:
        c = _fetch(u)
        if c:
            base = os.path.basename(u.split("?")[0]) or "app.js"
            try:
                with open(os.path.join(tmpdir, f"{n}_{base}"), "w", errors="ignore") as f:
                    f.write(c)
                n += 1
            except OSError:
                pass
    if not n:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return "(could not download JS)"
    _, out, err = run_cmd(["retire", "--jspath", tmpdir, "--outputformat", "text"])
    shutil.rmtree(tmpdir, ignore_errors=True)
    return (out + "\n" + err).strip() or "(no vulnerable libraries found)"


def run_dalfox(param_urls):
    if shutil.which("dalfox") is None:
        return "(dalfox not installed)"
    if not param_urls:
        return "(no parameterized URLs to test)"
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    for u in param_urls:
        tmp.write(u + "\n")
    tmp.close()
    _, out, _ = run_cmd(["dalfox", "file", tmp.name,
                            "--silence", "--no-color", "--skip-bav"]
                           + (["--waf-evasion", "--delay", STEALTH_DALFOX_DELAY,
                               "--worker", STEALTH_DALFOX_WORKER] if STEALTH else []),
                           timeout=1200 if STEALTH else 900)
    try:
        os.unlink(tmp.name)
    except OSError:
        pass
    return out.strip() or "(no XSS found)"


def run_nuclei_dast(param_urls, base_url, rate, concurrency):
    targets = param_urls or [base_url]
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    for u in targets:
        tmp.write(u + "\n")
    tmp.close()
    cmd = ["nuclei", "-l", tmp.name, "-dast", "-silent",
           "-rate-limit", rate, "-concurrency", concurrency]
    _, out, err = run_cmd(cmd, timeout=1200)
    try:
        os.unlink(tmp.name)
    except OSError:
        pass
    out = out.strip()
    if out:
        return out
    err = err.strip()
    if err:
        return "(no DAST findings)\nnote: " + err.splitlines()[-1][:160]
    return "(no DAST findings)"


def run_wapiti(url):
    if shutil.which("wapiti") is None:
        return "(wapiti not installed)"
    tmp = tempfile.NamedTemporaryFile(mode="r", suffix=".txt", delete=False)
    tmp.close()
    run_cmd(["wapiti", "-u", url, "--flush-session", "-f", "txt", "-o", tmp.name,
             "--max-scan-time", "600", "--verify-ssl", "0"]
            + (["--tasks", "1"] if STEALTH else []), timeout=1200)
    res = ""
    try:
        with open(tmp.name, "r", errors="ignore") as f:
            res = f.read().strip()
    except OSError:
        pass
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    if len(res) > 4000:
        res = res[:4000] + "\n... (truncated)"
    return res or "(no output)"


# ----------------------------------------------------------------------
# Secret / info-disclosure scan (pure stdlib, no extra tools required)
# ----------------------------------------------------------------------
SECRET_PATTERNS = [
    # Non-overlapping domain part (no '.' inside the label class next to the
    # required literal '.') so this cannot backtrack quadratically on a hostile blob.
    ("email",          re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("slack_token",    re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("jwt",            re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("private_key",    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("bearer_token",   re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{12,}")),
    ("assignment",     re.compile(r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|"
                                  r"apikey|access[_-]?token|auth[_-]?token|token)"
                                  r"\s*[:=]\s*[\"']([^\"'\s<>]{4,80})[\"']")),
]
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
SCRIPT_SRC   = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_NON_TLD = ("png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "json",
            "map", "ico", "woff", "woff2", "ttf", "mp4", "webm")


def _fetch(url, timeout=15, cap=2_000_000):
    """Fetch a URL (stdlib). Returns text, or '' on any failure. Size-capped."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vantage-secretscan"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(cap).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def scan_blob(content, src):
    """Return a list of (kind, value, source) findings from one text blob."""
    out = []
    for name, rx in SECRET_PATTERNS:
        for m in rx.finditer(content):
            val = m.group(0).strip()
            if name == "email":
                dom = val.rsplit(".", 1)[-1].lower()
                if dom in _NON_TLD:
                    continue
            if len(val) > 120:
                val = val[:120] + "…"
            out.append((name, val, src))
    if "-->" in content:
        for c in HTML_COMMENT.findall(content):
            c = " ".join(c.split())
            if c:
                out.append(("html-comment", c[:160] + ("…" if len(c) > 160 else ""), src))
    return out


def run_secretscan(base_url, crawl_output=""):
    contents = {}
    # Cap external fetches so a hostile/compromised target cannot make the
    # "quiet" secret scan pull thousands of 2 MB scripts (bandwidth/time DoS).
    MAX_FETCHES = 40
    html = _fetch(base_url)
    if html:
        contents[base_url] = html
        for m in SCRIPT_SRC.findall(html):
            if len(contents) >= MAX_FETCHES:
                break
            u = urljoin(base_url.rstrip("/") + "/", m)
            if u not in contents:
                c = _fetch(u)
                if c:
                    contents[u] = c
    for ln in crawl_output.splitlines():
        if len(contents) >= MAX_FETCHES:
            break
        ln = ln.strip()
        if ln.split("?")[0].lower().endswith((".js", ".json", ".map")) and ln not in contents:
            c = _fetch(ln)
            if c:
                contents[ln] = c

    findings, seen = [], set()
    for src, content in contents.items():
        for kind, val, s in scan_blob(content, src):
            key = (kind, val)
            if key not in seen:
                seen.add(key)
                findings.append((kind, val, s))

    if not findings:
        return "(no obvious secrets / emails / comments found)"
    lines = [f"total findings: {len(findings)}", ""]
    for kind, val, src in findings[:200]:
        lines.append(f"[{kind}] {val}")
        lines.append(f"    source: {src}")
    if len(findings) > 200:
        lines.append(f"... ({len(findings) - 200} more, truncated)")
    return "\n".join(lines)


# ----------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------
REPORT_SECTIONS = (
    ("whatweb",  "WHATWEB (fingerprint)"),
    ("wafw00f",  "WAFW00F (WAF detection)"),
    ("naabu",    "OPEN PORTS (naabu)"),
    ("nmap",     "NMAP -sV"),
    ("tls",      "TLS / CERT (tlsx / sslscan)"),
    ("nuclei",   "NUCLEI"),
    ("nikto",    "NIKTO"),
    ("gobuster", "GOBUSTER (200 only)"),
    ("ffuf",     "FFUF (200 only)"),
    ("crawl",    "CRAWL (katana + hakrawler)"),
    ("arjun",    "ARJUN (hidden parameters)"),
    ("retire",   "RETIRE.JS (vulnerable JS libraries)"),
    ("dalfox",   "DALFOX (XSS) [--force]"),
    ("nuclei_dast", "NUCLEI DAST (active fuzzing) [--force]"),
    ("wapiti",   "WAPITI (full DAST) [--force]"),
    ("sqlmap",   "SQLMAP (parameterized URLs)"),
    ("secrets",  "SECRETS / INFO DISCLOSURE (source scan)"),
)


def write_report(path, target, all_subs, live, results, use_syn, katana_headless):
    bar = "=" * 72
    sub = "-" * 72
    with open(path, "w", encoding="utf-8") as f:
        f.write(bar + "\n")
        f.write(" VANTAGE RECON REPORT\n")
        f.write(f" Target        : {target}\n")
        f.write(f" Date          : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write(f" nmap mode     : {'-sS (SYN)' if use_syn else '-sT (connect - no root)'}\n")
        f.write(f" katana mode   : {'headless (JS/SPA)' if katana_headless else 'standard'}\n")
        f.write(bar + "\n\n")

        f.write(f"[ DISCOVERED SUBDOMAINS ]   total: {len(all_subs)}\n")
        f.write(sub + "\n")
        if all_subs:
            for s in sorted(all_subs):
                f.write(f"  - {s}\n")
        else:
            f.write("  (none - normal for a single/local target)\n")
        f.write("\n")

        f.write(f"[ LIVE (httpx) TARGETS ]   total: {len(live)}\n")
        f.write(sub + "\n")
        for u in live:
            f.write(f"  - {u}\n")
        f.write("\n\n")

        for url, entry in results.items():
            f.write(bar + "\n")
            f.write(f" TARGET: {url}\n")
            f.write(bar + "\n\n")
            for key, title in REPORT_SECTIONS:
                if key in entry:
                    f.write(f">>> {title}\n")
                    f.write(sub + "\n")
                    f.write(entry[key] + "\n\n")


# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------
CONSENT_FILE = os.path.join(
    os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config"),
    "vantage", "consent.json")

CONSENT_TEXT = """
  VANTAGE — AUTHORIZED USE ONLY
  -----------------------------
  Vantage runs ACTIVE scans (port scans, nuclei, nikto, optional sqlmap and
  DAST fuzzing). Running these against systems you do not own or lack WRITTEN
  authorization to test is illegal in most jurisdictions and can cause
  disruption. You confirm you will ONLY scan:
     * systems you own, or
     * targets you have explicit written authorization to test, or
     * intentionally-vulnerable practice labs / CTF environments.
  You accept full responsibility for how you use this tool.
"""


def check_authorized_use(assume_yes: bool) -> bool:
    """One-time typed authorized-use acknowledgement, persisted so it is asked
    only once per user (mirrors Strix Archer's consent gate)."""
    try:
        with open(CONSENT_FILE, encoding="utf-8") as f:
            if json.load(f).get("accepted") is True:
                return True
    except Exception:
        pass
    print(_c(CONSENT_TEXT, C.YELLOW))
    if assume_yes:
        log_info("authorized-use auto-accepted via --i-am-authorized")
        ok = True
    else:
        try:
            ans = input(_c("  Type 'I AGREE' to continue: ", C.BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        ok = ans.upper() in ("I AGREE", "AGREE", "YES")
    if ok:
        try:
            os.makedirs(os.path.dirname(CONSENT_FILE), exist_ok=True)
            with open(CONSENT_FILE, "w", encoding="utf-8") as f:
                json.dump({"accepted": True, "at": datetime.now().isoformat()}, f)
        except Exception:
            pass
    return ok


def main():
    epilog = (
        "examples:\n"
        "  sudo vantage localhost:3000 --katana-headless\n"
        "  sudo vantage localhost:3000 --katana-headless --skip-nikto\n"
        "  sudo vantage http://localhost:3000 -o report.txt\n"
        "  vantage example.com --no-install --no-color\n\n"
        "install as a command:\n"
        "  sudo install -m 755 recon_pipeline.py /usr/local/bin/vantage\n\n"
        "notes:\n"
        "  * run with sudo for -sS SYN scans and apt-based auto-install\n"
        "  * use only against systems you own or are authorized to test\n"
    )
    parser = VantageParser(
        prog="vantage",
        description="Vantage - recon automation pipeline for authorized targets.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"Vantage {VERSION}")
    parser.add_argument("target",
                        help="target domain or URL (e.g. localhost:3000, "
                             "http://localhost:3000, example.com)")
    parser.add_argument("-o", "--output", default=None, help="report file path")
    parser.add_argument("-w", "--wordlist", default=GOBUSTER_WORDLIST,
                        help="gobuster wordlist path")
    parser.add_argument("--httpx-bin", default=HTTPX_BIN,
                        help="httpx binary name (e.g. httpx-toolkit)")
    parser.add_argument("--profile", choices=list(PROFILES), default=None,
                        help="preset flag bundle: recon (discovery only) | "
                             "fast (quick pass) | stealth (WAF-evasive everyday) | "
                             "thorough (max coverage, WAF-evasive)")
    parser.add_argument("--katana-headless", action="store_true",
                        help="run katana headless (reveals SPA/REST endpoints)")
    parser.add_argument("--all-active", action="store_true",
                        help="run the full active scan set on EVERY live host "
                             "(default: active scan on the primary/entered domain only; "
                             "subdomains get whatweb only)")
    parser.add_argument("--no-install", action="store_true",
                        help="do NOT auto-install missing tools")
    parser.add_argument("--no-color", action="store_true",
                        help="disable colored output")
    parser.add_argument("--update-nuclei", action="store_true",
                        help="force 'nuclei -update-templates' before scanning")
    parser.add_argument("--debug", action="store_true",
                        help="print the exact command line of every tool that runs")
    parser.add_argument("--fast", action="store_true",
                        help="IDS/WAF-safe speed-up: fewer templates (auto) + "
                             "-no-interactsh, WITHOUT raising the request rate")
    parser.add_argument("--stealth", action="store_true",
                        help="WAF-evasion: low rate + inter-request delay/jitter + "
                             "tools' own WAF-evasion modes (dalfox --waf-evasion, etc.)")
    parser.add_argument("--nuclei-rate", default=NUCLEI_RATE_LIMIT,
                        help=f"nuclei requests/sec (default {NUCLEI_RATE_LIMIT}; "
                             "lower it to stay under IDS/WAF thresholds)")
    parser.add_argument("--nuclei-concurrency", default=NUCLEI_CONCURRENCY,
                        help=f"nuclei parallel templates (default {NUCLEI_CONCURRENCY})")
    parser.add_argument("--nuclei-auto", action="store_true",
                        help="nuclei automatic scan (-as): only tech-matched templates")
    parser.add_argument("--nuclei-tags", default="",
                        help="restrict nuclei to tags, e.g. "
                             "exposure,misconfig,tech,default-login,xss,sqli")
    parser.add_argument("--nuclei-severity", default="",
                        help="restrict nuclei severities, e.g. info,low,medium,high,critical")
    parser.add_argument("--skip-amass", action="store_true", help="skip amass")
    parser.add_argument("--skip-dnsx", action="store_true",
                        help="skip dnsx resolution/validation of subdomains")
    parser.add_argument("--skip-wafw00f", action="store_true", help="skip wafw00f (primary)")
    parser.add_argument("--skip-tls", action="store_true", help="skip TLS/cert check (primary)")
    parser.add_argument("--skip-ffuf", action="store_true", help="skip ffuf (primary)")
    parser.add_argument("--ffuf-fs", default="",
                        help="ffuf: filter out this response size (SPA default page)")
    parser.add_argument("--sqlmap", action="store_true",
                        help="run sqlmap on parameterized URLs (primary only; OFF by default, "
                             "heavy + WAF-tripping)")
    parser.add_argument("--force", action="store_true",
                        help="also run the heavy DAST scanners: dalfox (XSS) + "
                             "nuclei -dast (active fuzzing) + wapiti (full DAST)")
    parser.add_argument("--skip-arjun", action="store_true", help="skip arjun (parameter discovery)")
    parser.add_argument("--skip-retire", action="store_true", help="skip retire.js (vulnerable JS libs)")
    parser.add_argument("--skip-whatweb", action="store_true", help="skip whatweb")
    parser.add_argument("--skip-naabu", action="store_true", help="skip naabu")
    parser.add_argument("--skip-nmap", action="store_true", help="skip nmap")
    parser.add_argument("--skip-nuclei", action="store_true", help="skip nuclei")
    parser.add_argument("--skip-nikto", action="store_true", help="skip nikto")
    parser.add_argument("--skip-gobuster", action="store_true", help="skip gobuster")
    parser.add_argument("--skip-crawl", action="store_true", help="skip crawling")
    parser.add_argument("--skip-secrets", action="store_true", help="skip secret scan")
    parser.add_argument("--i-am-authorized", action="store_true",
                        help="skip the one-time authorized-use confirmation (for automation/CI)")
    args = parser.parse_args()

    # apply a profile preset (additive: turns flags ON; your explicit flags win)
    if args.profile:
        for k, v in PROFILES[args.profile].items():
            setattr(args, k, getattr(args, k) or v)

    global USE_COLOR
    if args.no_color or not sys.stdout.isatty():
        USE_COLOR = False

    global DEBUG
    DEBUG = args.debug

    global STEALTH
    STEALTH = args.stealth

    print_banner()

    if not check_authorized_use(args.i_am_authorized):
        log_warn("authorized-use not confirmed — aborting.")
        sys.exit(1)

    if args.profile:
        log_info(f"profile '{args.profile}' -> "
                 + ", ".join(k for k, v in PROFILES[args.profile].items() if v))

    if STEALTH:
        log_info("stealth mode ON: low rate + delay/jitter + WAF-evasion "
                 "(dalfox/ffuf/gobuster/naabu/nuclei/wapiti)")

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    use_syn = is_root
    if not is_root:
        log_warn("not root -> nmap/naabu use connect scan; run with sudo for -sS")

    log_phase("Environment check")
    ensure_go_bin_on_path()
    missing = check_tools(args.httpx_bin)
    if not missing:
        log_result("tools", "all required tools present")
    else:
        log_warn("missing: " + ", ".join(missing))
        if args.no_install:
            log_info("auto-install disabled (--no-install)")
        else:
            log_step("auto-installing missing tools")
            missing = auto_install(missing, is_root)
        if missing:
            log_warn("still missing: " + ", ".join(missing) + " (their steps are skipped)")
        else:
            log_result("tools", "all tools ready")

    # Ensure a working ProjectDiscovery httpx (the python3-httpx CLI has no -l).
    if resolve_httpx(args.httpx_bin) is None:
        log_warn("no ProjectDiscovery httpx detected (python 'httpx' has no -l)")
        if not args.no_install:
            log_step("installing ProjectDiscovery httpx (httpx-toolkit)")
            try_install("httpx", is_root)
        chosen = resolve_httpx(args.httpx_bin)
        if chosen:
            log_result("httpx", f"using '{chosen}'")
        else:
            log_warn("still none -> built-in liveness fallback will be used")

    if not args.skip_nuclei:
        ensure_nuclei_templates(force=args.update_nuclei)

    # Install opt-in tools only when their flag is set.
    opt = []
    if args.force:
        opt += ["dalfox", "wapiti"]
    if args.sqlmap:
        opt += ["sqlmap"]
    opt = [t for t in opt if shutil.which(t) is None]
    if opt and not args.no_install:
        log_step("installing opt-in tools: " + ", ".join(opt))
        auto_install(opt, is_root)

    bare, probe = normalize_target(args.target)
    if not valid_host(bare):
        log_warn("invalid target host "
                 f"'{bare}' — must be a hostname or IP with no leading '-'")
        sys.exit(2)
    log_info(f"target domain: {bare}    probe: {probe}")

    log_phase("Subdomain enumeration")
    all_subs = set()
    all_subs |= run_subfinder(bare)
    all_subs |= run_sublist3r(bare)
    if not args.skip_amass:
        all_subs |= run_amass(bare)
    log_result("subdomains", f"{len(all_subs)} unique total")

    if not args.skip_dnsx:
        all_subs = run_dnsx(all_subs)

    # ALWAYS include the entered target itself (subfinder/amass often omit the
    # apex), so the entered domain is the one that gets the full scan.
    probe_targets = sorted(set(all_subs) | {probe})
    if not all_subs:
        log_info("no subdomains (normal for a local target) -> scanning target directly")

    # Drop any enumerated host that isn't a syntactically valid hostname/IP before
    # it can reach a scanner as a bare positional (subdomain-enum output is
    # untrusted). The entered target was already validated above.
    bad = {h for h in probe_targets if not valid_host(h)}
    if bad:
        log_warn(f"dropping {len(bad)} invalid enumerated host(s): "
                 + ", ".join(sorted(bad)[:5]) + ("…" if len(bad) > 5 else ""))
        probe_targets = [h for h in probe_targets if h not in bad]

    log_phase("Liveness check")
    live = run_httpx(probe_targets, args.httpx_bin)
    # Guarantee the entered target is present and becomes the primary, even if
    # httpx did not return it (e.g. apex not directly responsive but you still
    # want it treated as the primary target).
    entered_url = probe if "://" in probe else "http://" + probe
    if not any((urlparse(u).hostname or "") == bare for u in live):
        live.insert(0, entered_url)
        log_info(f"entered target added as primary: {entered_url}")
    if not live:
        live = [entered_url]

    log_phase("Per-host scanning")
    # effective nuclei rate/concurrency (stealth lowers them unless you set your own)
    n_rate = args.nuclei_rate
    n_conc = args.nuclei_concurrency
    if args.stealth:
        if n_rate == NUCLEI_RATE_LIMIT:
            n_rate = STEALTH_NUCLEI_RATE
        if n_conc == NUCLEI_CONCURRENCY:
            n_conc = STEALTH_NUCLEI_CONC
    # RULE: the ACTIVE set (naabu, wafw00f, nmap, tls, nuclei, nikto, gobuster,
    # ffuf, crawl, sqlmap, secrets) runs ONLY on the primary (entered) domain.
    # Every other live subdomain gets whatweb only (light identification).
    # With --all-active, the full active set runs on every live host too.
    primary = pick_primary(live, bare)
    log_info(f"primary (active scan) target: {primary}")
    if len(live) > 1 and not args.all_active:
        log_info("subdomains get whatweb only "
                 "(active scan is primary-only; use --all-active for all hosts)")
    elif len(live) > 1 and args.all_active:
        log_info("--all-active: full active scan will run on every live host")
    results = {}
    for i, url in enumerate(live, 1):
        log_target(i, len(live), url)
        entry = {}
        host = urlparse(url).hostname or url
        full = (url == primary) or args.all_active

        # whatweb (light, single request) runs on EVERY live host
        if not args.skip_whatweb:
            log_step("whatweb - technology fingerprint")
            entry["whatweb"] = run_whatweb(url)
            log_result("whatweb", first_line(entry["whatweb"]))

        # Subdomains without --all-active stop here — no active scan.
        if not full:
            log_info("subdomain -> whatweb only (no active scan; use --all-active)")
            results[url] = entry
            continue

        # ---------- active scan (primary, or every host with --all-active) ----------
        ports = []
        if not args.skip_naabu:
            log_step("naabu - fast port scan")
            ports = run_naabu(host, use_syn)
            entry["naabu"] = "\n".join(ports) if ports else "(no open ports found)"
            log_result("naabu", f"{len(ports)} open port(s): " + (", ".join(ports) or "-"))

        if not args.skip_wafw00f:
            log_step("wafw00f - WAF detection")
            entry["wafw00f"] = run_wafw00f(url)
            log_result("wafw00f", first_line(entry["wafw00f"]))

        if not args.skip_nmap:
            log_step("nmap - service/version detection")
            entry["nmap"] = run_nmap(url, use_syn, ports)
            n_open = sum(1 for l in entry["nmap"].splitlines() if "/tcp" in l and "open" in l)
            log_result("nmap", f"{n_open} service(s) identified")

        if not args.skip_tls:
            log_step("tls - certificate / cipher check")
            entry["tls"] = run_tls(host)
            log_result("tls", first_line(entry["tls"]))

        if not args.skip_nuclei:
            log_step("nuclei - vulnerability templates")
            # --fast reduces the template set (auto) + skips OOB, but keeps the
            # low request rate so an IDS/WAF is not tripped.
            ni = args.fast
            auto = args.nuclei_auto or (args.fast and not args.nuclei_tags and not args.nuclei_severity)
            entry["nuclei"] = run_nuclei(url, rate=n_rate,
                                         concurrency=n_conc, ni=ni,
                                         tags=args.nuclei_tags, severity=args.nuclei_severity,
                                         auto=auto)
            n = 0 if entry["nuclei"].startswith("(") else len([l for l in entry["nuclei"].splitlines() if l.strip()])
            log_result("nuclei", f"{n} finding(s)")
            if n == 0 and "note:" in entry["nuclei"]:
                log_warn("nuclei: " + entry["nuclei"].split("note:", 1)[1].strip()[:160])

        if not args.skip_nikto:
            log_step("nikto - web server checks (time-bounded)")
            entry["nikto"] = run_nikto(url)
            n = sum(1 for l in entry["nikto"].splitlines() if l.strip().startswith("+"))
            log_result("nikto", f"{n} note(s)")

        if not args.skip_gobuster:
            log_step("gobuster - content discovery (200 only)")
            entry["gobuster"] = run_gobuster(url, args.wordlist, GOBUSTER_THREADS)
            n = sum(1 for l in entry["gobuster"].splitlines() if "(Status:" in l)
            log_result("gobuster", f"{n} path(s)")

        if not args.skip_ffuf:
            log_step("ffuf - content discovery (200 only)")
            entry["ffuf"] = run_ffuf(url, args.wordlist, args.ffuf_fs)
            n = len([l for l in entry["ffuf"].splitlines() if l.strip() and not l.startswith("(")])
            log_result("ffuf", f"{n} path(s)")

        if not args.skip_crawl:
            log_step("katana + hakrawler - crawling endpoints")
            kat = run_katana(url, args.katana_headless)
            hak = run_hakrawler(url)
            entry["crawl"] = merge_urls(kat, hak)
            _crawl_urls = _num(entry['crawl'], r'total unique URLs:\s*(\d+)')
            log_result("crawl", f"{_crawl_urls} unique URL(s)")

        # parameterized URLs feed the param-based scanners (dalfox/dast/sqlmap)
        param_urls = _param_urls(entry.get("crawl", ""))

        if not args.skip_arjun:
            log_step("arjun - hidden parameter discovery")
            disp, aparams = run_arjun(url)
            entry["arjun"] = disp
            log_result("arjun", disp[:80])
            if aparams:
                param_urls.append(url.rstrip("/") + "?" + "&".join(f"{p}=1" for p in aparams[:15]))

        if not args.skip_retire:
            log_step("retire.js - vulnerable JS libraries")
            entry["retire"] = run_retirejs(entry.get("crawl", ""))
            log_result("retire", first_line(entry["retire"]))

        if args.force:
            log_step("dalfox - XSS scan (--force)")
            entry["dalfox"] = run_dalfox(param_urls)
            log_result("dalfox", first_line(entry["dalfox"]))

            log_step("nuclei DAST - active parameter fuzzing (--force)")
            entry["nuclei_dast"] = run_nuclei_dast(param_urls, url,
                                                   n_rate, n_conc)
            nd = 0 if entry["nuclei_dast"].startswith("(") else len([l for l in entry["nuclei_dast"].splitlines() if l.strip()])
            log_result("nuclei-dast", f"{nd} finding(s)")

            log_step("wapiti - full DAST scan (--force)")
            entry["wapiti"] = run_wapiti(url)
            log_result("wapiti", first_line(entry["wapiti"]))

        if args.sqlmap:
            log_step("sqlmap - SQL injection on parameterized URLs")
            entry["sqlmap"] = run_sqlmap(entry.get("crawl", ""))
            log_result("sqlmap", first_line(entry["sqlmap"]))

        if not args.skip_secrets:
            log_step("secret scan - emails / creds / tokens in source")
            entry["secrets"] = run_secretscan(url, entry.get("crawl", ""))
            _secret_n = _num(entry['secrets'], r'total findings:\s*(\d+)')
            log_result("secrets", f"{_secret_n} finding(s)")

        results[url] = entry

    # Sanitize the target before using it in a default filename: `bare` can fall
    # back to the raw input (e.g. 'http://@/..' yields an empty hostname), which
    # could contain '/' or '..'. Keep only filename-safe characters.
    safe_bare = re.sub(r"[^A-Za-z0-9._-]", "_", bare)[:80] or "target"
    out_path = args.output or f"recon_{safe_bare}_{datetime.now():%Y%m%d_%H%M%S}.txt"
    try:
        parent = os.path.dirname(os.path.abspath(out_path))
        if parent:
            os.makedirs(parent, exist_ok=True)   # don't fail after a long scan
        write_report(out_path, args.target, all_subs, live, results, use_syn, args.katana_headless)
    except OSError as e:
        fallback = os.path.join(tempfile.gettempdir(), f"recon_{safe_bare}.txt")
        log_warn(f"could not write {out_path} ({e}) - saving to {fallback} instead")
        try:
            write_report(fallback, args.target, all_subs, live, results, use_syn, args.katana_headless)
            out_path = fallback
        except OSError as e2:
            log_warn(f"report could not be saved: {e2}")

    log_phase("Summary")
    log_info(f"subdomains discovered : {len(all_subs)}")
    log_info(f"live targets          : {len(live)}")
    for url, entry in results.items():
        parts = []
        if "naabu" in entry:
            parts.append("ports:" + str(0 if entry["naabu"].startswith("(") else len(entry["naabu"].split())))
        if "nuclei" in entry:
            parts.append("nuclei:" + str(0 if entry["nuclei"].startswith("(") else len([l for l in entry["nuclei"].splitlines() if l.strip()])))
        if "gobuster" in entry:
            parts.append("paths:" + str(sum(1 for l in entry["gobuster"].splitlines() if "(Status:" in l)))
        if "crawl" in entry:
            parts.append("urls:" + str(_num(entry["crawl"], r"total unique URLs:\s*(\d+)")))
        if "secrets" in entry:
            parts.append("secrets:" + str(_num(entry["secrets"], r"total findings:\s*(\d+)")))
        log_info(f"  {url}  ->  " + "  ".join(parts))
    log_result("report saved", out_path)
    print()


if __name__ == "__main__":
    main()
