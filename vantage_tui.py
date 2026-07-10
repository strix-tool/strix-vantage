#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vantage TUI
-----------
A terminal UI wrapper around vantage.py. Runs Vantage as a subprocess and
streams its live output into a scrollable panel, plus a History tab to browse
and re-open past reports. The core tool (vantage.py) is unchanged; this only
needs `textual`.

Install:  pip install textual --break-system-packages
Run:      sudo python3 vantage_tui.py     (sudo -> full -sS + auto-install)

Looks for vantage.py next to this file; override with
    VANTAGE_PATH=/path/to/vantage.py python3 vantage_tui.py
"""

import glob
import os
import shlex
import subprocess
import sys
import time

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (Button, Checkbox, Footer, Header, Input, Label,
                             OptionList, RichLog, Select, TabbedContent,
                             TabPane, Tree)
from textual.widgets.option_list import Option

HERE = os.path.dirname(os.path.abspath(__file__))
VANTAGE = os.environ.get("VANTAGE_PATH") or os.path.join(HERE, "vantage.py")

PROFILES = ["recon", "fast", "stealth", "thorough"]
FLAGS = ["katana-headless", "fast", "stealth", "force", "sqlmap",
         "all-active", "no-install"]


def colorize(line: str) -> Text:
    """Turn a plain vantage log line into a colored Text (by its marker)."""
    if any(c in line for c in "█╗╔═║╚╝"):
        return Text(line, style="cyan")
    if line.strip().startswith("$"):
        return Text(line, style="bold magenta")
    if "✔" in line:
        return Text(line, style="green")
    if "▶" in line or "●" in line:
        return Text(line, style="bold cyan")
    if "] ! " in line or line.strip().startswith("!"):
        return Text(line, style="yellow")
    if "dbg " in line:
        return Text(line, style="dim")
    if ">>>" in line or "===" in line or "---" in line:
        return Text(line, style="bold cyan")
    if "finished" in line and "—" in line:
        return Text(line, style="bold green")
    return Text(line)


def parse_report(text: str):
    """Parse a Vantage .txt report into [(host_label, [(tool_label, [lines])])]."""
    hosts = []
    cur_host = None
    cur_tool = None

    def new_host(label):
        nonlocal cur_host, cur_tool
        cur_host = (label, [])
        hosts.append(cur_host)
        cur_tool = None

    def new_tool(label):
        nonlocal cur_tool
        cur_tool = (label, [])
        cur_host[1].append(cur_tool)

    new_host("Report info")
    for raw in text.splitlines():
        line = raw.rstrip()
        s = line.strip()
        if not s or set(s) <= set("=-"):          # separator / blank lines
            continue
        if s.startswith("TARGET:"):
            new_host(s[len("TARGET:"):].strip())
            continue
        if s.startswith(">>>"):
            new_tool(s[3:].strip())
            continue
        if cur_tool is None:
            new_tool("info")
        cur_tool[1].append(line)
    out = []
    for h, tools in hosts:
        tools = [(tl, ls) for tl, ls in tools if ls]
        if tools:
            out.append((h, tools))
    return out


class VantageTUI(App):
    TITLE = "Vantage"
    SUB_TITLE = "recon TUI"

    CSS = """
    #form { height: auto; border: round $primary; padding: 1 2; margin: 1 1 0 1; }
    #flags { height: auto; }
    #buttons { height: auto; }
    #log { border: round $secondary; height: 1fr; padding: 0 1; margin: 1; }
    #status { color: $text-muted; margin-top: 1; }
    Label { margin-top: 1; }
    Input { margin: 0 0 1 0; }
    Button { margin: 1 1 0 0; }
    Checkbox { width: auto; margin: 0 2 0 0; }
    #history-box { height: 1fr; margin: 1; }
    #history-list { width: 45; border: round $primary; }
    #history-tree { width: 1fr; border: round $secondary; padding: 0 1; }
    #refresh-history { margin: 0 1 1 1; }
    """

    BINDINGS = [
        ("f5", "run_scan", "Run"),
        ("ctrl+l", "clear_log", "Clear"),
        ("f6", "refresh_history", "Refresh history"),
        ("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._scanning = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="tab-scan"):
            with TabPane("Scan", id="tab-scan"):
                with Vertical(id="form"):
                    yield Label("Target")
                    yield Input(placeholder="e.g. localhost:3000  or  example.com", id="target")
                    yield Label("Profile")
                    yield Select([(p, p) for p in PROFILES], prompt="(no profile)", id="profile")
                    yield Label("Flags")
                    with Horizontal(id="flags"):
                        for fid in FLAGS:
                            yield Checkbox(fid, id=fid)
                    yield Input(placeholder="extra flags, e.g. --nuclei-rate 2 --skip-nikto",
                                id="extra")
                    with Horizontal(id="buttons"):
                        yield Button("\u25b6 Run scan", id="run", variant="primary")
                        yield Button("Clear log", id="clear")
                        yield Button("Quit", id="quit", variant="error")
                    yield Label("", id="status")
                yield RichLog(id="log", wrap=True, highlight=False, markup=False)
            with TabPane("History", id="tab-history"):
                with Horizontal(id="history-box"):
                    yield OptionList(id="history-list")
                    yield Tree("(select a report)", id="history-tree")
                yield Button("Refresh", id="refresh-history")
        yield Footer()

    def on_mount(self) -> None:
        self._refresh_history()

    # ---- events ----
    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "quit":
            self.exit()
        elif bid == "clear":
            self.action_clear_log()
        elif bid == "run":
            self.action_run_scan()
        elif bid == "refresh-history":
            self.action_refresh_history()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        fname = event.option_id
        if fname:
            self._load_report(fname)

    # ---- actions ----
    def action_clear_log(self) -> None:
        self.query_one("#log", RichLog).clear()

    def action_refresh_history(self) -> None:
        self._refresh_history()

    def action_run_scan(self) -> None:
        target = self.query_one("#target", Input).value.strip()
        log = self.query_one("#log", RichLog)
        if not target:
            log.write(Text("Enter a target first.", style="bold red"))
            return
        if self._scanning:
            log.write(Text("A scan is already running.", style="yellow"))
            return
        cmd = self._build_cmd(target)
        log.write(Text("$ " + " ".join(cmd), style="bold magenta"))
        self._scanning = True
        self.query_one("#run", Button).disabled = True
        self.query_one("#status", Label).update("Status: running\u2026")
        self._scan_worker(cmd)

    # ---- helpers ----
    def _refresh_history(self) -> None:
        ol = self.query_one("#history-list", OptionList)
        ol.clear_options()
        files = sorted(glob.glob("recon_*.txt"),
                       key=lambda f: os.path.getmtime(f), reverse=True)
        if not files:
            ol.add_option(Option("(no reports yet)", id=""))
            return
        for f in files:
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(f)))
            ol.add_option(Option(f"{ts}   {f}", id=f))


    def _load_report(self, fname: str) -> None:
        tree = self.query_one("#history-tree", Tree)
        tree.reset(os.path.basename(fname))
        try:
            with open(fname, "r", errors="ignore") as fh:
                parsed = parse_report(fh.read())
        except OSError as e:
            tree.root.add_leaf(f"cannot open: {e}")
            return
        for host_label, tools in parsed:
            hnode = tree.root.add(host_label, expand=True)
            for tool_label, lines in tools:
                tnode = hnode.add(Text(tool_label, style="bold cyan"))
                for ln in lines:
                    tnode.add_leaf(ln)
        tree.root.expand()

    def _build_cmd(self, target: str):
        cmd = [sys.executable, VANTAGE, target, "--no-color"]
        prof = self.query_one("#profile", Select).value
        if isinstance(prof, str) and prof in PROFILES:
            cmd += ["--profile", prof]
        for fid in FLAGS:
            if self.query_one("#" + fid, Checkbox).value:
                cmd.append("--" + fid)
        extra = self.query_one("#extra", Input).value.strip()
        if extra:
            cmd += shlex.split(extra)
        return cmd

    def _write(self, renderable) -> None:
        self.query_one("#log", RichLog).write(renderable)

    def _finish(self, report) -> None:
        self._scanning = False
        self.query_one("#run", Button).disabled = False
        msg = "Status: done" + (f"   \u00b7   report: {report}" if report else "")
        self.query_one("#status", Label).update(msg)
        self._refresh_history()
        if report and os.path.isfile(report):
            self.query_one(TabbedContent).active = "tab-history"
            self._load_report(report)

    @work(exclusive=True, thread=True)
    def _scan_worker(self, cmd) -> None:
        report = None
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in proc.stdout:
                line = line.rstrip("\n")
                self.call_from_thread(self._write, colorize(line))
                if "report saved" in line and "\u00b7" in line:
                    report = line.split("\u00b7", 1)[1].strip()
            proc.wait()
            self.call_from_thread(
                self._write,
                Text(f"\u2014 finished (exit {proc.returncode}) \u2014", style="bold green"))
        except FileNotFoundError:
            self.call_from_thread(
                self._write,
                Text(f"Cannot find vantage at: {VANTAGE}\n"
                     f"Put vantage.py next to this file, or set VANTAGE_PATH.",
                     style="bold red"))
        except Exception as e:  # noqa
            self.call_from_thread(self._write, Text(f"error: {e}", style="bold red"))
        finally:
            self.call_from_thread(self._finish, report)


if __name__ == "__main__":
    VantageTUI().run()
