#!/usr/bin/env python3
"""Regenerate screenshots/sftp-audit-light-dark.png.

Simple SFTP Audit Tool is a desktop app: at screenshot time there is no
Python backend to talk to. Its UI already degrades gracefully outside
pywebview (every window.pywebview.api call is guarded), so this tool serves
the page and its assets from a temp folder, hands the page a finished audit
result the way runAudit() normally would, and calls the page's own render(r)
to paint it.

Nothing here touches the working copy. The UI file, the icon, and the fonts
folder are copied into a temp folder and served from there; the real files
are only ever read, never written.

    python tools/screenshot/make_screenshot.py

Options:
    --keep            leave the temp folder in place for inspection
    --build-tools P   path to the build-tools repo (default: sibling folder)
"""

import http.server
import json
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scene  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))

OUT_IMAGE = os.path.join(REPO_ROOT, "screenshots",
                         "sftp-audit-light-dark.png")

# Each theme is laid out at this size and captured at half scale, giving two
# 900x??? halves and the composite the README uses. The height is tuned to
# close just under the last card, before the version bar, with no empty band
# beneath the content.
LAYOUT_WIDTH = 1800
LAYOUT_HEIGHT = 1720
CAPTURE_SCALE = 0.5


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def read_app_version() -> str:
    path = os.path.join(REPO_ROOT, "simple_sftp_audit_tool.py")
    with open(path, encoding="utf-8") as f:
        source = f.read()
    match = re.search(r'APP_VERSION\s*=\s*"([^"]+)"', source)
    if not match:
        fail(f"could not find APP_VERSION in {path}")
    return match.group(1)


def stage_ui(temp_dir: str) -> None:
    """Copy just what the page needs into temp_dir."""
    shutil.copy2(os.path.join(REPO_ROOT, "simple_sftp_audit_tool-UI.html"),
                 os.path.join(temp_dir, "index.html"))
    shutil.copy2(os.path.join(REPO_ROOT, "simple_sftp_audit_tool.png"),
                 temp_dir)
    shutil.copytree(os.path.join(REPO_ROOT, "fonts"),
                     os.path.join(temp_dir, "fonts"))


def build_setup_script(version: str) -> str:
    """JavaScript that hands the page a finished audit result and drives the
    page's own render path.

    The UI's boot only runs on the pywebviewready event, which never fires in
    a plain browser, so this sets the version bar the way initVersion() would
    and calls render(r) the way runAudit() would after a successful
    window.pywebview.api.run_audit(), each guarded so the script still works
    if a function is renamed or removed.
    """
    result = scene.result()
    return (
        f"document.getElementById('ver-bar').textContent = 'v' + {json.dumps(version)};"
        "if (typeof applyTheme === 'function') applyTheme('dark');"
        f"if (typeof render === 'function') render({json.dumps(result)});"
    )


def write_capture_config(temp_dir: str, port: int, version: str) -> str:
    config = {
        "url": f"http://127.0.0.1:{port}/index.html",
        "width": LAYOUT_WIDTH,
        "height": LAYOUT_HEIGHT,
        "scale": CAPTURE_SCALE,
        "outDir": "shots",
        "waitFor": "typeof render === 'function'",
        "setup": build_setup_script(version),
        "settleMs": 500,
        "shots": [
            {"name": "light", "script": "applyTheme('light')"},
            {"name": "dark", "script": "applyTheme('dark')"},
        ],
    }
    path = os.path.join(temp_dir, "shots.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    return path


def run(cmd: list, label: str) -> None:
    result = subprocess.run(cmd, cwd=REPO_ROOT)
    if result.returncode != 0:
        fail(f"{label} failed with exit code {result.returncode}")


def main(argv: list) -> None:
    keep = "--keep" in argv
    build_tools = os.path.join(os.path.dirname(REPO_ROOT), "build-tools")
    if "--build-tools" in argv:
        index = argv.index("--build-tools") + 1
        if index >= len(argv):
            fail("--build-tools needs a path after it")
        build_tools = argv[index]

    capture_script = os.path.join(build_tools, "screenshot", "capture.mjs")
    compose_script = os.path.join(build_tools, "screenshot", "compose.py")
    for path in (capture_script, compose_script):
        if not os.path.exists(path):
            fail(f"missing {path}. Pass --build-tools with the repo path.")

    version = read_app_version()
    temp_dir = tempfile.mkdtemp(prefix="sftp-audit-screenshot-")
    httpd = None

    try:
        stage_ui(temp_dir)

        port = free_port()

        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def __init__(self, *a, **kw):
                super().__init__(*a, directory=temp_dir, **kw)

        httpd = socketserver.TCPServer(("127.0.0.1", port), Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

        config_path = write_capture_config(temp_dir, port, version)
        run(["node", capture_script, config_path], "capture")

        shots_dir = os.path.join(temp_dir, "shots")
        run([sys.executable, compose_script, OUT_IMAGE,
             os.path.join(shots_dir, "light.png"),
             os.path.join(shots_dir, "dark.png")], "compose")
    finally:
        if httpd is not None:
            httpd.shutdown()
        if keep:
            print(f"temp folder kept at {temp_dir}")
        else:
            shutil.rmtree(temp_dir, ignore_errors=True)
            if os.path.exists(temp_dir):
                print(f"WARNING: could not remove {temp_dir}", file=sys.stderr)

    print(f"seeded version: v{version}")
    print(f"updated {OUT_IMAGE}")


if __name__ == "__main__":
    main(sys.argv[1:])
