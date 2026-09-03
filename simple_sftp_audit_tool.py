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

import ctypes
from ctypes import wintypes
import errno
import io
import os
import re
import socket
import ssl
import sys
import threading
import time
import traceback
import json
import urllib.error
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

from ssh_audit.ssh2_kexdb import SSH2_KexDB

APP_VERSION = "1.6.2"
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

    args = ["ssh-audit", "-j", "-4", "-t", "10", "-p", str(port)]
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


def _parse_algorithm_section(entries):
    """Build the {name, status, reason, key_size, fail_labels, warn_labels} list
    for one of kex/key/enc/mac. fail_labels/warn_labels keep ssh-audit's raw
    FAIL_*/WARN_* constant strings (see ssh_audit.ssh2_kexdb.SSH2_KexDB) so the
    grading model can reason about each specific weakness; status/reason stay
    as the coarse fail/warn/good summary the display code already relies on."""
    out = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("algorithm")
        if not name:
            continue
        notes = entry.get("notes") or {}
        fails = notes.get("fail") or []
        warns = notes.get("warn") or []
        status = "fail" if fails else "warn" if warns else "good"
        reason = "; ".join(fails + warns)
        key_size = str(entry["keysize"]) if isinstance(entry.get("keysize"), int) else None
        out.append({
            "name": name, "status": status, "reason": reason, "key_size": key_size,
            "fail_labels": list(fails), "warn_labels": list(warns),
        })
    return out


def _flatten_recommendations(recommendations):
    """Flatten the nested {level: {action: {alg_type: [{name, notes}]}}} dict
    into a flat list of human-readable strings. Guarded so a malformed shape
    is skipped instead of raising."""
    flat = []
    if not isinstance(recommendations, dict):
        return flat
    action_verbs = {"del": "Remove", "add": "Add", "chg": "Change"}
    for level in ("critical", "warning", "informational"):
        by_action = recommendations.get(level)
        if not isinstance(by_action, dict):
            continue
        for action, verb in action_verbs.items():
            by_alg_type = by_action.get(action)
            if not isinstance(by_alg_type, dict):
                continue
            for entries in by_alg_type.values():
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    name = entry.get("name")
                    if not name:
                        continue
                    text = f"{verb} {name}"
                    notes = entry.get("notes")
                    if notes:
                        text += f" ({notes})"
                    flat.append(text)
    return flat


def _parse_json(output):
    """Parse ssh-audit's `-j` JSON output into a structured dict. Returns None
    when no JSON object can be extracted (e.g. the engine failed to connect
    and printed only an [exception] line); the caller treats that as the
    no-data path."""
    text = _clean(output).strip()
    data = None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                data = json.loads(text[start:end + 1])
            except (json.JSONDecodeError, ValueError):
                return None
        else:
            return None

    if not isinstance(data, dict):
        return None

    banner = data.get("banner") or {}
    software = banner.get("software") or banner.get("raw") or ""

    compression = [c for c in (data.get("compression") or []) if isinstance(c, str)]

    security_issues = []
    protocol = banner.get("protocol") or ""
    ssh_v1 = isinstance(protocol, str) and protocol.split(".")[0] == "1"
    if ssh_v1:
        security_issues.append(
            "SSH v1 enabled -- SSH v1 can be exploited to recover plaintext passwords"
        )
    for note in data.get("additional_notes") or []:
        if isinstance(note, str) and note:
            security_issues.append(note)

    fingerprints = []
    for fp in data.get("fingerprints") or []:
        if not isinstance(fp, dict):
            continue
        fingerprints.append(f"{fp.get('hostkey')} ({fp.get('hash_alg')}): {fp.get('hash')}")

    return {
        "software": software,
        "compression": compression,
        "security_issues": security_issues,
        "ssh_v1": ssh_v1,
        "kex": _parse_algorithm_section(data.get("kex")),
        "key": _parse_algorithm_section(data.get("key")),
        "enc": _parse_algorithm_section(data.get("enc")),
        "mac": _parse_algorithm_section(data.get("mac")),
        "fingerprints": fingerprints,
        "recommendations": _flatten_recommendations(data.get("recommendations")),
    }


# --------------------------------------------------------------------------- #
# Grading model: tier-ceiling (see blueprint.md for the full model and its
# citations). ssh-audit attaches one of a fixed, pinned set of FAIL_*/WARN_*
# reason strings (ssh_audit.ssh2_kexdb.SSH2_KexDB) to each algorithm it flags.
# We tier the REASON, not the algorithm name: each reason is worth Tier 0
# (broken/prohibited), Tier 1 (deprecated, must migrate), Tier 2 (discouraged
# but not broken), or "not graded" (shown, never lowers the letter). The worst
# tier seen anywhere sets the ceiling letter; a demerit count built from how
# many algorithms land in each tier drives a +/- modifier within that letter.
# --------------------------------------------------------------------------- #

# Tier 0 - broken / prohibited -> ceiling F.
_TIER_0_LABELS = {
    SSH2_KexDB.FAIL_PLAINTEXT,
    SSH2_KexDB.FAIL_RC4,
    SSH2_KexDB.FAIL_MD5,
    SSH2_KexDB.FAIL_DES,
    SSH2_KexDB.FAIL_3DES,
    SSH2_KexDB.FAIL_BLOWFISH,
    SSH2_KexDB.FAIL_CAST,
    SSH2_KexDB.FAIL_LOGJAM_ATTACK,
    SSH2_KexDB.FAIL_1024BIT_MODULUS,
}

# Tier 1 - deprecated, must migrate -> ceiling C.
_TIER_1_LABELS = {
    SSH2_KexDB.FAIL_SHA1,
    SSH2_KexDB.FAIL_IDEA,
    SSH2_KexDB.FAIL_RIJNDAEL,
    SSH2_KexDB.FAIL_SMALL_ECC_MODULUS,
    SSH2_KexDB.FAIL_SEED,
}

# Tier 2 - discouraged, weaker but not broken -> ceiling B.
_TIER_2_LABELS = {
    SSH2_KexDB.WARN_CIPHER_MODE,
    SSH2_KexDB.WARN_ENCRYPT_AND_MAC,
    SSH2_KexDB.WARN_2048BIT_MODULUS,
    SSH2_KexDB.WARN_BLOCK_SIZE,
    SSH2_KexDB.WARN_TAG_SIZE,
    SSH2_KexDB.WARN_TAG_SIZE_96,
    SSH2_KexDB.FAIL_RIPEMD,
    SSH2_KexDB.FAIL_SERPENT,
    SSH2_KexDB.FAIL_UNPROVEN,
}

# Not graded - shown as information only, never lowers the letter.
_NOT_GRADED_LABELS = {
    SSH2_KexDB.WARN_NOT_PQ_SAFE,
    SSH2_KexDB.WARN_RNDSIG_KEY,
    SSH2_KexDB.FAIL_NSA_BACKDOORED_CURVE,
    SSH2_KexDB.FAIL_UNTRUSTED,
    SSH2_KexDB.WARN_EXPERIMENTAL,
}

# Case B - ssh-audit itself could not classify the algorithm. Outside our
# control (depends what a remote server advertises), so it is not a build
# failure like an untiered label would be. Shown as unrecognized; never counts
# as secure, never sets or dodges a ceiling.
_UNKNOWN_LABEL = SSH2_KexDB.FAIL_UNKNOWN

_TIER_MAP = {}
for _label in _TIER_0_LABELS:
    _TIER_MAP[_label] = 0
for _label in _TIER_1_LABELS:
    _TIER_MAP[_label] = 1
for _label in _TIER_2_LABELS:
    _TIER_MAP[_label] = 2

# Credited "modern algorithm" names for the A+ modifier (Curve25519, Ed25519,
# AES-GCM/ChaCha20 AEAD ciphers, or an Encrypt-then-MAC mode).
_CREDIT_KEX = {"curve25519-sha256", "curve25519-sha256@libssh.org",
               "sntrup761x25519-sha512@openssh.com"}
_CREDIT_ENC = {"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"}

_GRADE_COLORS = {
    "A": "#5ce39b",  # green
    "B": "#6db3ff",  # blue
    "C": "#f0b860",  # amber
    "F": "#ff6b7a",  # red
}


def _algorithm_worst_tier(alg):
    """Return (tier, is_unknown) for one parsed algorithm dict (as built by
    _parse_algorithm_section). tier is the worst graded tier (0/1/2) among its
    labels, or None when it has no graded finding (no labels, or only
    not-graded/unknown ones). is_unknown is True when FAIL_UNKNOWN (Case B) is
    one of its labels."""
    labels = alg["fail_labels"] + alg["warn_labels"]
    is_unknown = _UNKNOWN_LABEL in labels
    tiers = [_TIER_MAP[label] for label in labels if label in _TIER_MAP]
    tier = min(tiers) if tiers else None
    return tier, is_unknown


def _is_credited_modern(section, name):
    lname = (name or "").lower()
    if section == "kex":
        return lname in _CREDIT_KEX
    if section == "key":
        return lname == "ssh-ed25519"
    if section == "enc":
        return lname in _CREDIT_ENC
    if section == "mac":
        return "-etm@" in lname
    return False


def _counts(parsed):
    """Score every algorithm across kex/key/enc/mac. Each algorithm counts
    once, at its worst graded tier (see _algorithm_worst_tier). Returns a dict
    with the display counts (fails/warns/goods) plus the grading inputs the
    ceiling and modifier need: the worst tier seen anywhere, the demerit
    counts per tier, and whether a credited modern algorithm is present.

    fails = algorithms whose worst graded tier is 0 or 1.
    warns = algorithms whose worst graded tier is 2.
    goods = algorithms with no graded finding (including ones that carry only
    not-graded labels). Case B (FAIL_UNKNOWN-only) algorithms count as none of
    the three: shown as unrecognized, never secure, never a ceiling.

    nist_curve is True when any algorithm carries FAIL_NSA_BACKDOORED_CURVE
    (the reliable "a NIST P-curve is present" signal), which does not set a
    tier ceiling but does trigger the A- soft cap in _grade."""
    fails = warns = goods = 0
    tier1_count = tier2_count = 0
    worst_tier = None
    has_credit = False
    nist_curve = False
    for sec in ("kex", "key", "enc", "mac"):
        for alg in parsed[sec]:
            tier, is_unknown = _algorithm_worst_tier(alg)
            if tier is not None:
                if worst_tier is None or tier < worst_tier:
                    worst_tier = tier
                if tier <= 1:
                    fails += 1
                    if tier == 1:
                        tier1_count += 1
                else:
                    warns += 1
                    tier2_count += 1
            elif not is_unknown:
                goods += 1
            if _is_credited_modern(sec, alg["name"]):
                has_credit = True
            if SSH2_KexDB.FAIL_NSA_BACKDOORED_CURVE in alg["fail_labels"]:
                nist_curve = True
    return {
        "fails": fails, "warns": warns, "goods": goods,
        "worst_tier": worst_tier, "tier1_count": tier1_count,
        "tier2_count": tier2_count, "has_credit": has_credit,
        "nist_curve": nist_curve,
    }


def _grade(counts, ssh_v1=False):
    """Ceiling letter = worst tier present (Tier 0 -> F, Tier 1 -> C, Tier 2
    -> B, none -> A), then a +/- modifier from the demerit total
    d = 3 * tier1_count + tier2_count. SSH v1 is a hard cap straight to F.

    NIST-curve soft cap: a NIST P-curve (FAIL_NSA_BACKDOORED_CURVE) does not
    set a tier ceiling, since it is FIPS-standard and carries no CVE, but it
    is not the same as being hardened to curve25519/ed25519-only. So it caps
    an otherwise A+/A grade at A-. No effect at B or below."""
    worst_tier = counts["worst_tier"]
    if ssh_v1 or worst_tier == 0:
        return "F", _GRADE_COLORS["F"]

    d = 3 * counts["tier1_count"] + counts["tier2_count"]

    if worst_tier == 1:
        if d <= 4:
            letter = "C+"
        elif d >= 10:
            letter = "C-"
        else:
            letter = "C"
        return letter, _GRADE_COLORS["C"]

    if worst_tier == 2:
        if d <= 2:
            letter = "B+"
        elif d >= 7:
            letter = "B-"
        else:
            letter = "B"
        return letter, _GRADE_COLORS["B"]

    if counts["nist_curve"]:
        letter = "A-"
    else:
        letter = "A+" if counts["has_credit"] else "A"
    return letter, _GRADE_COLORS["A"]


def _has_sha1_fail(section):
    """True when any algorithm in a parsed section (list of {status, reason})
    was flagged with a SHA-1-related failure by ssh-audit's own notes."""
    return any(a["status"] == "fail" and "SHA-1" in a["reason"] for a in section)


def _checklist(parsed):
    items = []
    all_kex = [a["name"].lower() for a in parsed["kex"]]
    all_key = [a["name"].lower() for a in parsed["key"]]
    all_enc = [a["name"].lower() for a in parsed["enc"]]
    all_mac = [a["name"].lower() for a in parsed["mac"]]

    if _has_sha1_fail(parsed["key"]):
        items.append({"status": "bad", "text": "Supports SHA-1 host key signatures (e.g. ssh-rsa) - deprecated"})
    else:
        items.append({"status": "good", "text": "No SHA-1 host key signature algorithms"})

    modern_kex = ["curve25519-sha256", "curve25519-sha256@libssh.org",
                  "sntrup761x25519-sha512@openssh.com"]
    if any(k in all_kex for k in modern_kex):
        items.append({"status": "good", "text": "Supports modern key exchange (Curve25519)"})
    else:
        items.append({"status": "warn", "text": "No Curve25519 key exchange support"})

    if _has_sha1_fail(parsed["kex"]):
        items.append({"status": "bad", "text": "Supports weak SHA-1 key exchange algorithms"})
    else:
        items.append({"status": "good", "text": "No weak SHA-1 key exchange algorithms"})

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


# ----------------------------------------------------------------------------
# Local prefs store. One JSON file next to the app holds EVERY persisted
# setting: theme, window geometry, and anything added later. Always read-
# merge-write through load_prefs / save_prefs. Never overwrite the file with
# a single key, or the next setting you add silently wipes the others.
# ----------------------------------------------------------------------------

def _pref_path() -> str:
    return os.path.join(_exe_dir(), "simple_sftp_audit_tool.pref")


def load_prefs() -> dict:
    """Load the full prefs dict. Tolerant of a missing or corrupt file."""
    try:
        with open(_pref_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_prefs(prefs: dict) -> bool:
    try:
        with open(_pref_path(), "w", encoding="utf-8") as f:
            json.dump(prefs, f)
        return True
    except Exception:
        return False


# Window geometry persistence. Save and restore the ABSOLUTE window frame
# rectangle via Win32, found by the window title. GetWindowRect (save) and
# SetWindowPos (restore) share one frame-based, physical-pixel coordinate
# space, so the rect round-trips exactly at any DPI or monitor layout. Do NOT
# pass x/y into create_window and do NOT use window.move: pywebview's Qt
# backend applies those pre-show and relative to the primary screen, so the
# window lands on the wrong monitor, drifts down by the title-bar height each
# launch, and slides sideways at non-100% scaling.

def _win32():
    u = ctypes.windll.user32
    u.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    u.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                               ctypes.c_int, ctypes.c_int, wintypes.UINT]
    return u


def _own_window_handle(title):
    """HWND of our own top-level window with this title.

    FindWindowW matches by title across the whole desktop, so with a second
    instance open it can return the other copy's window. Enumerate instead and
    keep only a window owned by this process.
    """
    try:
        u = ctypes.windll.user32
        WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        u.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
        u.EnumWindows.restype = wintypes.BOOL
        u.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        u.GetWindowThreadProcessId.restype = wintypes.DWORD
        u.GetWindowTextLengthW.argtypes = [wintypes.HWND]
        u.GetWindowTextLengthW.restype = ctypes.c_int
        u.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        u.GetWindowTextW.restype = ctypes.c_int
        u.IsWindowVisible.argtypes = [wintypes.HWND]
        u.IsWindowVisible.restype = wintypes.BOOL

        own_pid = os.getpid()
        found = {"hwnd": None}

        def _callback(hwnd, lparam):
            if not u.IsWindowVisible(hwnd):
                return True
            pid = wintypes.DWORD()
            u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value != own_pid:
                return True
            length = u.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return True
            buf = ctypes.create_unicode_buffer(length + 1)
            u.GetWindowTextW(hwnd, buf, length + 1)
            if buf.value != title:
                return True
            found["hwnd"] = hwnd
            return False   # stop enumerating, we found it

        proc = WNDENUMPROC(_callback)   # kept alive for the duration of the call below
        u.EnumWindows(proc, 0)
        return found["hwnd"]
    except Exception:
        return None


def _save_geometry(win) -> None:
    """Save the absolute frame rect (physical px) via Win32. Wire to `closing`.
    Wrapped end to end so a failure here can never block the window from closing."""
    try:
        u = _win32()
        hwnd = _own_window_handle(win.title)
        if not hwnd:
            return
        r = wintypes.RECT()
        if not u.GetWindowRect(hwnd, ctypes.byref(r)):
            return
        x, y, w, h = r.left, r.top, r.right - r.left, r.bottom - r.top
        if x <= -30000 or y <= -30000:   # minimized sentinel, not a real spot
            return
        if w <= 0 or h <= 0:
            return
        prefs = load_prefs()
        prefs["window"] = {"x": x, "y": y, "width": w, "height": h}
        save_prefs(prefs)
    except Exception:
        pass


def _restore_geometry(win) -> None:
    """Restore the saved frame rect via Win32. Wire to `shown` (after the OS
    window exists). Validate before applying; never raise."""
    try:
        geo = load_prefs().get("window")
        if not isinstance(geo, dict):
            return
        x, y, w, h = geo.get("x"), geo.get("y"), geo.get("width"), geo.get("height")
        for v in (x, y, w, h):
            if not isinstance(v, int) or isinstance(v, bool):
                return
        if w <= 0 or h <= 0:
            return
        # Is a point in the title bar still on a connected monitor?
        point = wintypes.POINT(x + 100, y + 30)
        user32 = ctypes.windll.user32
        user32.MonitorFromPoint.argtypes = [wintypes.POINT, wintypes.DWORD]
        user32.MonitorFromPoint.restype = wintypes.HMONITOR
        if not user32.MonitorFromPoint(point, 0):   # MONITOR_DEFAULTTONULL
            return
        u = _win32()
        hwnd = _own_window_handle(win.title)
        if not hwnd:
            return
        SWP_NOZORDER, SWP_NOACTIVATE = 0x0004, 0x0010
        u.SetWindowPos(hwnd, None, x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE)
    except Exception:
        pass


class DebugLog:
    def __init__(self):
        self._on = False
        self._path = None
        self._lock = threading.Lock()
    def set_enabled(self, on):
        with self._lock:
            on = bool(on)
            if on and not self._path:
                self._path = os.path.join(_exe_dir(), "Debug_Log_" + datetime.now().strftime("%m%d%Y_%H%M%S") + ".txt")
                try:
                    with open(self._path, "w", encoding="utf-8") as f:
                        f.write("=== Simple SFTP Audit Tool debug log ===\n")
                except Exception:
                    self._path = None
                    self._on = False
                    return False
            self._on = on
            return True
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


def _update_error_reason(exc: BaseException) -> str:
    """Turn a check_update exception into a short, plain-language reason to
    show in the UI. Pure and network-free: takes the already-raised exception,
    never touches the network itself.

    Each branch is specific to a failure that can actually cause it, and
    names a next step where there is a sensible one. Subclasses are checked
    before their parents: SSLCertVerificationError and SSLEOFError/
    SSLZeroReturnError before the generic ssl.SSLError, and the specific
    ConnectionError subclasses and socket.gaierror before the generic OSError
    branch (socket.timeout is an alias of TimeoutError, and both are OSError
    subclasses)."""
    # HTTPError is a URLError subclass but carries its own .code, so classify
    # it before unwrapping anything.
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 403:
            return (
                "GitHub is rate-limiting update checks from this network. "
                "Try again later."
            )
        if exc.code == 404:
            return "No published release was found."
        if 500 <= exc.code < 600:
            return f"GitHub is having trouble on its end (HTTP {exc.code})."
        return f"GitHub returned an error (HTTP {exc.code})."

    if isinstance(exc, json.JSONDecodeError):
        return (
            "GitHub returned something unexpected. This often means a proxy "
            "or a guest wifi sign-in page answered instead."
        )

    # A plain URLError wraps the underlying cause (ssl.SSLError, socket.timeout,
    # a DNS/socket OSError, ...) in its .reason; unwrap it to classify the
    # actual cause, but remember it came from a URLError for the fallback below.
    is_url_error = isinstance(exc, urllib.error.URLError)
    cause = exc.reason if is_url_error and exc.reason is not None else exc

    if isinstance(cause, ssl.SSLCertVerificationError):
        return (
            "GitHub's certificate could not be verified. This usually means "
            "antivirus or a network filter is inspecting HTTPS traffic."
        )
    if isinstance(cause, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
        return "The secure connection was cut off during the handshake with GitHub."
    if isinstance(cause, ssl.SSLError):
        return "The secure connection to GitHub failed."
    if isinstance(cause, socket.gaierror):
        return (
            "The address for api.github.com could not be looked up. Check "
            "DNS or the internet connection."
        )
    if isinstance(cause, (socket.timeout, TimeoutError)):
        return "GitHub didn't respond in time."
    if isinstance(cause, (ConnectionRefusedError, ConnectionResetError)):
        return (
            "The connection was refused or reset. A firewall or proxy may "
            "be blocking it."
        )
    if isinstance(cause, OSError) and getattr(cause, "errno", None) == errno.ENETUNREACH:
        return "No network connection."
    if is_url_error:
        return "Couldn't reach GitHub. Check the internet connection."

    text = f"{type(exc).__name__}: {exc}"
    if len(text) > 120:
        text = text[:117] + "..."
    return text


def _valid_release_tag(tag):
    """True only when tag looks like a version number (optional leading v, digits and dots)."""
    if not isinstance(tag, str) or not tag:
        return False
    return re.fullmatch(r"v?\d+(?:\.\d+){0,3}", tag) is not None


def _valid_release_url(url):
    """True only when url points at this repo's GitHub releases page."""
    if not isinstance(url, str):
        return False
    return url.startswith("https://github.com/%s/releases/" % GITHUB_REPO)


_ALLOWED_LINK_PREFIXES = (
    "https://jde-projects.com",
    "https://github.com/jtesta/ssh-audit",
    "https://github.com/JDE-Projects/Simple-SFTP-Audit-Tool",
)


def _allowed_external_url(url):
    """True only when url matches (or is a sub-path of) one of the allowed link prefixes."""
    if not isinstance(url, str):
        return False
    return any(url == prefix or url.startswith(prefix + "/") for prefix in _ALLOWED_LINK_PREFIXES)


class Api:
    def set_debug(self, enabled):
        ok = debug.set_enabled(enabled)
        debug.log("Debug enabled" if enabled and ok else "Debug disabled")
        return {"ok": ok, "enabled": debug.is_enabled()}

    def check_update(self):
        """Compare the latest published release to APP_VERSION. Quiet in the UI on
        failure (see _update_error_reason), but always logged when debug is on."""
        try:
            req = Request("https://api.github.com/repos/%s/releases/latest" % GITHUB_REPO,
                          headers={"User-Agent": "Simple-SFTP-Audit-Tool", "Accept": "application/vnd.github+json"})
            with urlopen(req, timeout=10) as r:
                data = json.loads(r.read().decode())
            tag_raw = data.get("tag_name") or ""
            tag = tag_raw.lstrip("v") if _valid_release_tag(tag_raw) else ""
            url_raw = data.get("html_url") or ""
            fallback_url = "https://github.com/%s/releases/latest" % GITHUB_REPO
            url = url_raw if _valid_release_url(url_raw) else fallback_url
            update = bool(tag) and self._is_newer(tag, APP_VERSION)
            debug.log("check_update", {"latest": tag, "current": APP_VERSION})
            return {"ok": True, "current": APP_VERSION, "latest": tag,
                    "update": update, "url": url}
        except Exception as e:
            debug.log("check_update failed", "%s: %s" % (type(e).__name__, e))
            return {"ok": False, "current": APP_VERSION, "reason": _update_error_reason(e), "error": str(e)}

    def _is_newer(self, latest, current):
        def parts(v):
            out = []
            for x in v.split("."):
                try:
                    out.append(int(x))
                except ValueError:
                    out.append(0)
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
        parsed = _parse_json(output)
        if parsed is None:
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

        total = sum(len(parsed[sec]) for sec in ("kex", "key", "enc", "mac"))
        has_banner = bool(parsed["software"])

        if total > 0:
            counts = _counts(parsed)
            grade, color = _grade(counts, ssh_v1=parsed["ssh_v1"])
            debug.log("AUDIT CLASSIFICATION", {
                "decision": "graded", "grade": grade,
                "fails": counts["fails"], "warns": counts["warns"], "goods": counts["goods"],
            })
            return {
                "ok": True, "host": host, "port": port,
                "grade": grade, "grade_color": color,
                "counts": {"fails": counts["fails"], "warns": counts["warns"], "goods": counts["goods"]},
                "software": parsed["software"],
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

    # --- theme preference (goes through the shared prefs store above) -------
    def get_theme(self):
        theme = load_prefs().get("theme")
        return theme if theme in ("dark", "light") else "dark"

    def save_theme(self, theme):
        if theme not in ("dark", "light"):
            return {"ok": False}
        prefs = load_prefs()
        prefs["theme"] = theme
        if save_prefs(prefs):
            debug.log("Theme set to %s" % theme)
            return {"ok": True}
        debug.log("Could not save theme pref")
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
            if _allowed_external_url(url):
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


_mutex_handle = None   # module-level: must live for the process lifetime
IS_SECOND_INSTANCE = False   # set True in main() when the user chooses to run a second copy

def _acquire_single_instance(mutex_name: str) -> bool:
    # Name convention: "JDE_Simple{Thing}Tool_SingleInstance"
    # Session-local (no "Global\" prefix): each Windows session (e.g. RDP,
    # fast user switching) gets its own instance instead of colliding across users.
    global _mutex_handle
    try:
        # use_last_error=True: ctypes.windll's GetLastError() can be clobbered
        # by ctypes-internal calls, so read the error via ctypes.get_last_error() instead.
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _mutex_handle = kernel32.CreateMutexW(None, False, mutex_name)
        return ctypes.get_last_error() != 183   # ERROR_ALREADY_EXISTS
    except Exception:
        return True   # fail open: never block launch over a mutex error

def _prompt_second_instance(app_title: str) -> bool:
    # Native message box only: runs before pywebview/Qt exists, so no Qt dialog is available yet.
    try:
        text = f"{app_title} is already running.\n\nOpen a second instance?"
        MB_YESNO_ICONQUESTION = 0x00000024
        result = ctypes.windll.user32.MessageBoxW(None, text, app_title, MB_YESNO_ICONQUESTION)
        return result == 6   # IDYES
    except Exception:
        return True   # fail open: if the box can't be shown, launch proceeds


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main():
    # Use the Windows certificate store for TLS instead of the bundled CA list,
    # so antivirus/network filters that inject their own root cert (common on
    # managed laptops) don't break the GitHub update check. Runs before the
    # Api object exists, so there's no logger yet to record a fallback; if
    # truststore is missing or fails, urllib silently keeps using its default
    # bundled CA list instead.
    try:
        import truststore
        truststore.inject_into_ssl()
    except Exception:
        pass

    global IS_SECOND_INSTANCE
    if not _acquire_single_instance("JDE_SimpleSFTPAuditTool_SingleInstance"):
        if not _prompt_second_instance("Simple SFTP Audit Tool"):
            sys.exit(0)
        IS_SECOND_INSTANCE = True

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

    # Geometry save/restore locates the window by enumerating this process's
    # own windows, so the lookup itself can't cross instances. Even so, a
    # second instance should not adopt or overwrite the first instance's
    # saved position. Only the first instance restores or saves geometry.
    if not IS_SECOND_INSTANCE:
        window.events.shown += lambda: _restore_geometry(window)

        def _on_closing():
            _save_geometry(window)
            return True
        window.events.closing += _on_closing

    try:
        webview.start(gui="qt", icon=resource_path(ICON_PNG))
    except TypeError:
        # older pywebview without the icon kwarg
        webview.start(gui="qt")


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    main()
