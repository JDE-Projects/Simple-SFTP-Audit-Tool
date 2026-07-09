#!/usr/bin/env python3
"""
Simple SFTP Audit Tool
by JDE-Projects

A standalone desktop tool that audits an SFTP/SSH server's security posture.
Wraps the ssh-audit engine, parses its output, and presents an at-a-glance
grade plus a color-coded breakdown in a pywebview (Qt) window.

Backend only: the UI lives in simple_sftp_audit_tool-UI.html. This module runs
ssh-audit in-process and returns parsed results to the page via the JS bridge.

Run from source:  python simple_sftp_audit_tool.py
Build the .exe:    Build_Simple_SFTP_Audit_Tool.bat
"""

import io
import os
import re
import socket
import sys
import threading
import time
import traceback
import json
from datetime import datetime
from urllib.request import Request, urlopen
from contextlib import redirect_stdout, redirect_stderr

# ssh-audit's DHEat rate test references socket.AF_UNIX unconditionally (an upstream
# bug present from its UNIX-socket-scanning feature through v3.9.0). That
# constant does not exist on Windows, so merely reading it crashes the rate test.
# We only ever audit TCP host:port targets, never UNIX-domain sockets, so that code
# branch is never legitimately taken. Define a harmless sentinel that no real address
# family equals, so the comparison evaluates False instead of raising. Remove if/when
# upstream guards the reference.
if not hasattr(socket, "AF_UNIX"):
    socket.AF_UNIX = -1

# Force the LGPL Qt binding (PySide6) so qtpy never picks up PyQt6 (GPL).
# setdefault leaves an explicit override in place if one is ever set.
os.environ.setdefault("QT_API", "pyside6")

import webview

APP_VERSION = "1.4.0"
GITHUB_REPO = "JDE-Projects/Simple-SFTP-Audit-Tool"  # owner/repo for update checks

APP_ID = "JDEProjects.SimpleSFTPAuditTool"
UI_FILE = "simple_sftp_audit_tool-UI.html"
ICON_PNG = "simple_sftp_audit_tool.png"

# Splash timing (runbook spec)
SPLASH_FLOOR = 5.0      # never close before this many seconds
SPLASH_CEILING = 30.0   # watchdog: always close by this many seconds


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def resource_path(rel):
    """Path to a bundled resource, in dev and in a PyInstaller bundle (onedir/onefile)."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)


# Strip ANSI/terminal escapes: colour/CSI, cursor save/restore (ESC 7/ESC 8),
# and other escape sequences. (Runbook: clean captured terminal output.)
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[78]|\x1b[@-Z\\-_]")


def _clean(line):
    return _ANSI.sub("", line).strip()


# --------------------------------------------------------------------------- #
# ssh-audit run + parse  (logic ported from the tested tkinter version)
# --------------------------------------------------------------------------- #
def _run_ssh_audit(host, port, rate_test=False):
    """Run ssh-audit in-process; return its raw text output (or '')."""
    from ssh_audit.ssh_audit import main as audit_main

    args = ["ssh-audit", "-v", "-4", "-t", "10", "-p", str(port)]
    if not rate_test:
        args.append("--skip-rate-test")
    args.append(host)
    original_argv = sys.argv
    sys.argv = args
    try:
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(buf):
            try:
                audit_main()
            except SystemExit:
                pass
        return buf.getvalue()
    finally:
        sys.argv = original_argv


def _parse(output):
    """Parse ssh-audit output into a structured dict."""
    parsed = {
        "software": "", "os": "", "compression": [], "security_issues": [],
        "kex": [], "key": [], "enc": [], "mac": [],
        "fingerprints": [], "recommendations": [],
    }
    section = None
    for raw in output.split("\n"):
        clean = _clean(raw)
        if not clean:
            continue

        if clean.startswith("# general"):
            section = "general"; continue
        elif clean.startswith("# key exchange algorithms"):
            section = "kex"; continue
        elif clean.startswith("# host-key algorithms"):
            section = "key"; continue
        elif clean.startswith("# encryption algorithms"):
            section = "enc"; continue
        elif clean.startswith("# message authentication"):
            section = "mac"; continue
        elif clean.startswith("# fingerprints"):
            section = "fingerprints"; continue
        elif clean.startswith("# algorithm recommendations"):
            section = "recommendations"; continue
        elif clean.startswith("# additional info"):
            section = "additional"; continue
        elif clean.startswith("# compression"):
            section = "compression"; continue
        elif clean.startswith("#"):
            section = None; continue

        if section == "general":
            if "(gen)" in clean:
                gen = clean.replace("(gen)", "").strip()
                low = gen.lower()
                if "software:" in low:
                    parsed["software"] = gen.split(":", 1)[1].strip() if ":" in gen else gen
                elif "os:" in low:
                    parsed["os"] = gen.split(":", 1)[1].strip() if ":" in gen else gen
                elif "banner:" in low:
                    banner = gen.split(":", 1)[1].strip() if ":" in gen else gen
                    if not parsed["software"]:
                        parsed["software"] = banner
                elif gen.startswith("SSH-") or "ssh" in low:
                    if not parsed["software"]:
                        parsed["software"] = gen
                if "[fail]" in clean.lower() or "[warn]" in clean.lower():
                    parsed["security_issues"].append(gen)

        elif section == "compression":
            if "(cmp)" in clean:
                mo = re.search(r"\(cmp\)\s+(\S+)", clean)
                if mo:
                    parsed["compression"].append(mo.group(1))

        elif section in ("kex", "key", "enc", "mac"):
            mo = re.match(r"\((?:kex|key|enc|mac)\)\s+(\S+)", clean)
            if mo:
                name = mo.group(1)
                size_mo = re.search(r"\((\d+)-bit\)", clean)
                key_size = size_mo.group(1) if size_mo else None
                status = "good"
                if "[fail]" in clean.lower():
                    status = "fail"
                elif "[warn]" in clean.lower():
                    status = "warn"
                reason = ""
                rmo = re.search(r"--\s+\[(fail|warn|info)\]\s+(.+)$", clean)
                if rmo and rmo.group(1) in ("fail", "warn"):
                    reason = rmo.group(2)
                existing = next((a for a in parsed[section] if a["name"] == name), None)
                if existing:
                    pri = {"fail": 3, "warn": 2, "good": 1}
                    if pri[status] > pri[existing["status"]]:
                        existing["status"] = status
                    if reason and reason not in existing["reason"]:
                        existing["reason"] = (existing["reason"] + "; " + reason).strip("; ")
                    if key_size and not existing.get("key_size"):
                        existing["key_size"] = key_size
                else:
                    parsed[section].append(
                        {"name": name, "status": status, "reason": reason, "key_size": key_size}
                    )

        elif section == "fingerprints":
            if "(fin)" in clean:
                parsed["fingerprints"].append(clean.replace("(fin)", "").strip())

        elif section == "recommendations":
            if "(rec)" in clean:
                parsed["recommendations"].append(clean.replace("(rec)", "").strip())

        elif section == "additional":
            if "(nfo)" in clean or "(inf)" in clean:
                txt = re.sub(r"\(nfo\)|\(inf\)", "", clean).strip()
                if txt:
                    parsed["security_issues"].append(txt)

    return parsed


def _counts(parsed):
    fails = warns = goods = 0
    for sec in ("kex", "key", "enc", "mac"):
        for alg in parsed[sec]:
            if alg["status"] == "fail":
                fails += 1
            elif alg["status"] == "warn":
                warns += 1
            else:
                goods += 1
    return fails, warns, goods


def _grade(fails, warns, goods):
    total = fails + warns + goods
    if total == 0:
        return "?", "#5a6678"
    if fails == 0 and warns == 0:
        return "A+", "#5ce39b"
    if fails == 0 and warns <= 2:
        return "A", "#4dd6c1"
    if fails == 0:
        return "B", "#6db3ff"
    if fails <= 2:
        return "C", "#f0b860"
    if fails <= 5:
        return "D", "#f0b860"
    return "F", "#ff6b7a"


def _checklist(parsed):
    items = []
    all_kex = [a["name"].lower() for a in parsed["kex"]]
    all_key = [a["name"].lower() for a in parsed["key"]]
    all_enc = [a["name"].lower() for a in parsed["enc"]]
    all_mac = [a["name"].lower() for a in parsed["mac"]]

    if "ssh-rsa" in all_key:
        items.append({"status": "bad", "text": "Supports ssh-rsa (SHA-1 signatures) - deprecated"})
    else:
        items.append({"status": "good", "text": "No SHA-1 signature algorithms (ssh-rsa not supported)"})

    modern_kex = ["curve25519-sha256", "curve25519-sha256@libssh.org",
                  "sntrup761x25519-sha512@openssh.com"]
    if any(k in all_kex for k in modern_kex):
        items.append({"status": "good", "text": "Supports modern key exchange (Curve25519)"})
    else:
        items.append({"status": "warn", "text": "No Curve25519 key exchange support"})

    weak_kex = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
                "diffie-hellman-group-exchange-sha1"]
    if any(k in all_kex for k in weak_kex):
        items.append({"status": "bad", "text": "Supports weak key exchange algorithms (SHA-1 based DH)"})
    else:
        items.append({"status": "good", "text": "No weak key exchange algorithms"})

    cbc = [c for c in all_enc if "-cbc" in c]
    if cbc:
        items.append({"status": "warn", "text": f"Supports CBC mode ciphers ({len(cbc)} found) - padding oracle risk"})
    else:
        items.append({"status": "good", "text": "No CBC mode ciphers"})

    aead = ["chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"]
    if any(c in all_enc for c in aead):
        items.append({"status": "good", "text": "Supports authenticated encryption (AEAD ciphers)"})
    else:
        items.append({"status": "warn", "text": "No AEAD ciphers (ChaCha20-Poly1305 or AES-GCM)"})

    if any("arcfour" in c for c in all_enc):
        items.append({"status": "bad", "text": "Supports arcfour/RC4 - broken cipher"})
    if any("3des" in c for c in all_enc):
        items.append({"status": "bad", "text": "Supports 3DES - weak cipher"})
    if any("md5" in m for m in all_mac):
        items.append({"status": "bad", "text": "Supports MD5-based MACs - weak hash"})

    if any("-etm@" in m for m in all_mac):
        items.append({"status": "good", "text": "Supports Encrypt-then-MAC (ETM) modes"})
    else:
        items.append({"status": "warn", "text": "No Encrypt-then-MAC (ETM) support"})

    if any("ed25519" in k for k in all_key):
        items.append({"status": "good", "text": "Supports Ed25519 host keys"})

    return items


# --------------------------------------------------------------------------- #
# JS-facing API
# --------------------------------------------------------------------------- #
def _exe_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


class DebugLog:
    def __init__(self):
        self._on = False; self._path = None; self._lock = threading.Lock()
    def set_enabled(self, on):
        with self._lock:
            on = bool(on)
            if on and not self._path:
                self._path = os.path.join(_exe_dir(), "Debug_Log_" + datetime.now().strftime("%m%d%Y_%H%M%S") + ".txt")
                try:
                    with open(self._path, "w", encoding="utf-8") as f:
                        f.write("=== Simple SFTP Audit Tool debug log ===\n")
                except Exception:
                    self._path = None; self._on = False; return False
            self._on = on; return True
    def is_enabled(self):
        return self._on
    def log(self, label, content=""):
        if not self._on or not self._path:
            return
        try:
            with self._lock, open(self._path, "a", encoding="utf-8") as f:
                f.write("[" + datetime.now().strftime("%H:%M:%S") + "] " + label + "\n")
                if content:
                    if isinstance(content, (dict, list)):
                        content = json.dumps(content, indent=2, default=str)
                    f.write(str(content) + "\n")
                f.write("\n")
        except Exception:
            pass


debug = DebugLog()


class Api:
    def set_debug(self, enabled):
        ok = debug.set_enabled(enabled)
        debug.log("Debug enabled" if enabled and ok else "Debug disabled")
        return {"ok": ok, "enabled": debug.is_enabled()}

    def check_update(self):
        try:
            req = Request("https://api.github.com/repos/%s/releases/latest" % GITHUB_REPO,
                          headers={"User-Agent": "Simple-SFTP-Audit-Tool", "Accept": "application/vnd.github+json"})
            with urlopen(req, timeout=8) as r:
                data = json.loads(r.read().decode())
            tag = (data.get("tag_name") or "").lstrip("v")
            return {"ok": True, "current": APP_VERSION, "latest": tag,
                    "update": self._is_newer(tag, APP_VERSION), "url": data.get("html_url", "")}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _is_newer(self, latest, current):
        def parts(v):
            out = []
            for x in v.split("."):
                try: out.append(int(x))
                except ValueError: out.append(0)
            return out + [0] * (3 - len(out))
        try:
            return parts(latest) > parts(current)
        except Exception:
            return False

    def run_audit(self, host, port, rate_test=False):
        """Called from the page. Returns a parsed result dict (or an error)."""
        host = (host or "").strip()
        try:
            port = int(str(port).strip())
        except (TypeError, ValueError):
            return {"ok": False, "error": "Port must be a number."}
        if not host:
            return {"ok": False, "error": "Please enter a hostname or IP address."}

        rate_test = bool(rate_test)
        debug.log("AUDIT", {"host": host, "port": port, "rate_test": rate_test})

        # Run the ssh-audit engine and capture its output.
        engine_error = False
        try:
            output = _run_ssh_audit(host, port, rate_test)
        except ImportError as e:
            return {"ok": False, "error": "ssh-audit library not found: %s" % e}
        except Exception:
            tb = traceback.format_exc()
            debug.log("SSH-AUDIT EXCEPTION", tb)
            engine_error = True
            output = ""

        debug.log("SSH-AUDIT RAW OUTPUT (len=%d)" % len(output), output)

        # Parse the output and classify the result.
        parsed = _parse(output)
        fails, warns, goods = _counts(parsed)
        total = fails + warns + goods
        has_banner = bool(parsed["software"])

        if total > 0:
            grade, color = _grade(fails, warns, goods)
            debug.log("AUDIT CLASSIFICATION", {
                "decision": "graded", "grade": grade,
                "fails": fails, "warns": warns, "goods": goods,
            })
            return {
                "ok": True, "host": host, "port": port,
                "grade": grade, "grade_color": color,
                "counts": {"fails": fails, "warns": warns, "goods": goods},
                "software": parsed["software"], "os": parsed["os"],
                "compression": parsed["compression"],
                "security_issues": parsed["security_issues"],
                "checklist": _checklist(parsed),
                "sections": {k: parsed[k] for k in ("kex", "key", "enc", "mac")},
                "recommendations": parsed["recommendations"],
                "fingerprints": parsed["fingerprints"],
                "rate_test": rate_test,
            }

        if has_banner:
            msg = (
                "Audit could not complete. "
                + host + ":" + str(port)
                + " responded with a banner ("
                + parsed["software"]
                + ") but returned no algorithm data, then closed the connection. "
                "The server may be throttling or refusing the full handshake. "
                "Try again, or test a server you control."
            )
            debug.log("AUDIT CLASSIFICATION", {
                "decision": "banner_only", "software": parsed["software"],
            })
            return {"ok": False, "error": msg, "host": host, "port": port}

        # No banner, empty output or engine error.
        if engine_error:
            msg = (
                "The scan engine hit an error while auditing "
                + host + ":" + str(port)
                + ". Enable the Debug log and re-run to capture details."
            )
        else:
            msg = (
                "Could not connect to " + host + ":" + str(port)
                + ". Can you reach this SFTP server from this machine and public IP?"
            )
        debug.log("AUDIT CLASSIFICATION", {
            "decision": "engine_error" if engine_error else "no_response",
        })
        return {"ok": False, "error": msg, "host": host, "port": port}

    # --- theme preference (local file next to the app) ---------------------
    def _pref_path(self):
        return os.path.join(_exe_dir(), "simple_sftp_audit_tool.pref")

    def _load_theme(self):
        try:
            with open(self._pref_path(), "r", encoding="utf-8") as f:
                theme = json.load(f).get("theme")
            return theme if theme in ("dark", "light") else "dark"
        except Exception:
            return "dark"

    def get_theme(self):
        return self._load_theme()

    def save_theme(self, theme):
        if theme not in ("dark", "light"):
            return {"ok": False}
        try:
            with open(self._pref_path(), "w", encoding="utf-8") as f:
                json.dump({"theme": theme}, f)
            debug.log("Theme set to %s" % theme)
            return {"ok": True}
        except Exception as e:
            debug.log("Could not save theme pref: %s" % e)
            return {"ok": False}

    def ssh_audit_version(self):
        try:
            from ssh_audit.ssh_audit import VERSION
            return VERSION
        except Exception:
            return ""

    def open_url(self, url):
        """Open an external link in the system browser (not the app window)."""
        import webbrowser
        try:
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                webbrowser.open(url)
        except Exception:
            pass
        return True

    def export_report(self, text):
        """Save the plain-text report to a file via a native save dialog."""
        if not isinstance(text, str):
            return {"ok": False, "error": "Nothing to export"}
        try:
            filename = "SSAT_Export_%s.txt" % time.strftime("%Y-%m-%d_%H-%M-%S")
            try:
                save_dialog = webview.FileDialog.SAVE
            except AttributeError:
                save_dialog = webview.SAVE_DIALOG  # older pywebview
            result = webview.windows[0].create_file_dialog(
                save_dialog,
                save_filename=filename,
                file_types=("Text file (*.txt)",),
            )
            if not result:
                return {"ok": True, "cancelled": True}
            path = result if isinstance(result, str) else result[0]
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            debug.log("Report exported to %s" % path)
            return {"ok": True, "path": path}
        except Exception as e:
            debug.log("Export failed: %s" % e)
            return {"ok": False, "error": str(e)}


# --------------------------------------------------------------------------- #
# Splash control (guarded; does nothing in source/dev runs)
# --------------------------------------------------------------------------- #
def _start_splash_closer(loaded_event):
    try:
        import pyi_splash  # only present in the PyInstaller bundle
    except Exception:
        return  # dev run: no splash

    def closer():
        start = time.time()
        # close once both the 5s floor has passed and the window is loaded,
        # or unconditionally at the watchdog ceiling.
        while time.time() - start < SPLASH_CEILING:
            if time.time() - start >= SPLASH_FLOOR and loaded_event.is_set():
                break
            time.sleep(0.1)
        try:
            pyi_splash.close()
        except Exception:
            pass

    threading.Thread(target=closer, daemon=True).start()


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main():
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
        except Exception:
            pass

    window = webview.create_window(
        "Simple SFTP Audit Tool",
        url=resource_path(UI_FILE),
        js_api=Api(),
        width=1000, height=820, min_size=(820, 600),
        background_color="#0a0e14",
    )

    loaded = threading.Event()
    window.events.loaded += lambda: loaded.set()
    _start_splash_closer(loaded)

    try:
        webview.start(gui="qt", icon=resource_path(ICON_PNG))
    except TypeError:
        # older pywebview without the icon kwarg
        webview.start(gui="qt")


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    main()
