# Simple SFTP Audit Tool

A standalone desktop tool that scans an SFTP/SSH server and shows its security posture at a glance. Enter a host and port, click **Run Audit**, and get an overall A-F grade, server details, and a color-coded breakdown of every algorithm the server offers.

Built by [JDE-Projects](https://github.com/JDE-Projects).

If you enjoyed this project and would like to buy me a coffee, check out my [Ko-fi](https://ko-fi.com/jdeprojects).

## Highlights

- **At-a-glance grade.** Every scan returns an overall A+ to F grade plus a count of failures, warnings, and secure items.
- **Plain-language security checklist.** Instead of just listing algorithms, it calls out what matters: SHA-1 signatures, weak key exchange, CBC ciphers, RC4/3DES, MD5 MACs, and whether modern options (Curve25519, Ed25519, AEAD, Encrypt-then-MAC) are present.
- **Organized by category.** Key exchange, host key, encryption, and MAC algorithms are grouped, each with red/yellow/green status and key sizes where reported.
- **Server fingerprint and details.** Software banner, detected OS, compression, and host key fingerprints.
- **One-click report.** Copy a full text report to the clipboard for tickets or records. Nothing is written to disk.

## How it works

- Backend: [ssh-audit](https://github.com/jtesta/ssh-audit), run in-process; its output is parsed into the visual layout.
- Window: pywebview on the Qt backend, UI in `simple_sftp_audit_tool-UI.html`.
- The scan is unauthenticated. It inspects what the server advertises during the handshake; it never logs in. There is no configuration or data file.

## Download and run

Grab the latest release zip from the [Releases](../../releases) page, extract it, and run `Simple SFTP Audit Tool.exe` from inside the extracted folder. Keep the folder together; the exe needs the files next to it. No Python or setup required. Windows only.

Because it is unsigned, Windows SmartScreen may warn about an unknown publisher the first time. Click **More info > Run anyway**.

## Verify this download (optional)

This release was built on GitHub from this public source - not on a personal machine - and is signed with a build-provenance attestation. To confirm a download is genuine, install the [GitHub CLI](https://cli.github.com) and run:

```
gh attestation verify SimpleSFTPAuditTool-vX.Y.Z.zip \
  --repo JDE-Projects/Simple-SFTP-Audit-Tool \
  --signer-repo JDE-Projects/Build-Tools
```

A `Verification succeeded!` line means the file was built by the published pipeline from this repo. You can also check the file against the published `.sha256`.

## Build from source (optional)

- Python 3 on PATH.
- `pip install -r requirements.txt` (pinned versions: PySide6, pywebview, qtpy, PyInstaller, and ssh-audit at a specific GitHub master commit — needs Git installed)

Keep `simple_sftp_audit_tool.py`, `simple_sftp_audit_tool-UI.html`, the `fonts/` folder, `simple_sftp_audit_tool.ico`, `simple_sftp_audit_tool.png`, and `simple_sftp_audit_tool-splash.png` together (the app loads the UI, fonts, and icon next to itself). Then either:

- **Run from source:** `python simple_sftp_audit_tool.py` (or double-click `Launch_Simple_SFTP_Audit_Tool.bat`)
- **Build the app:** double-click `Build_Simple_SFTP_Audit_Tool.bat`, which produces `dist\Simple SFTP Audit Tool\` (a folder containing `Simple SFTP Audit Tool.exe` and its files). Zip that folder to distribute it.

### Keeping ssh-audit current

The scanning engine is [ssh-audit](https://github.com/jtesta/ssh-audit). Its PyPI release lags well behind active development, so the build bundles ssh-audit from the project's **master** branch to get current algorithm coverage and post-quantum advisories. Building from master needs [Git](https://git-scm.com) on the build machine (not on end users).

For a reproducible, verifiable build, `requirements.txt` pins ssh-audit to one **exact master commit** rather than floating on whatever master is at build time. Before that pin is moved to a newer commit, the changes on ssh-audit's master since the pinned commit are reviewed for anything malicious or breaking and the tool's entry points are re-confirmed — *then* the commit is bumped and a new release built. So every release bundles a known, reviewed snapshot of ssh-audit, not an unaudited moving target.

## Using it

1. Type the server's hostname or IP in **Host/IP**, and the port in **Port** (default SFTP/SSH is 22). You can also paste `host:port` into the host box and it splits automatically.
2. Click **Run Audit** (or press Enter).
3. Read the grade and summary at the top, then scroll for the security checklist, advisories, and per-category algorithm lists. Green is good, yellow is a warning, red is a failure.
4. Click **Copy Report to Clipboard** for a plain-text version. **Clear** resets the view.

## What it checks

- **Key exchange algorithms** (flags SHA-1 based Diffie-Hellman, credits Curve25519)
- **Host key algorithms** (flags `ssh-rsa`/SHA-1, credits Ed25519)
- **Encryption ciphers** (flags CBC mode, RC4/arcfour, 3DES; credits ChaCha20-Poly1305 and AES-GCM)
- **Message authentication codes** (flags MD5-based MACs; credits Encrypt-then-MAC)
- **Server information** (software banner, OS guess, compression, host key fingerprints)

A few things worth knowing:

- The grade is derived from the count of failures and warnings across the four algorithm categories.
- Post-quantum / "Harvest Now, Decrypt Later" notices from newer ssh-audit builds show as warnings, not failures. A modern server without post-quantum hybrids is not broken, just not future-proofed yet.

## Security and privacy

- Nothing is written to disk. There is no config or data file. The only output is the on-screen result and the report you choose to copy to the clipboard.
- No credentials are used or stored. The tool never logs into the server.
- Only scan servers you own or are authorized to test.

## A note on how this was built

This project was built with AI assistance. The design decisions, feature direction, and real-world testing were directed by me. The code was written and revised with an AI assistant against that direction. Treat it like any community tool: review and test it before relying on it.

## Updates
Use Check for Updates (footer) to compare against the latest GitHub Release; if newer, it links you to the download. Silent when offline or while the repo is private.

## Debug log
Off by default. Toggle it in the footer to write `Debug_Log_MMDDYYYY_HHMMSS.txt` next to the app for the current run.

## License

Released under the [PolyForm Noncommercial License 1.0.0](LICENSE). Free for personal and any noncommercial use, modification, and noncommercial redistribution; commercial use is not permitted. Keep the copyright notice; no warranty.

This tool bundles third-party components: Qt via PySide6 (LGPL-3.0), pywebview (BSD-3-Clause), the Sora and JetBrains Mono fonts (OFL-1.1), and ssh-audit (MIT). Their notices and sources are in [THIRD-PARTY-LICENSES.txt](THIRD-PARTY-LICENSES.txt). The Qt binding is PySide6 (LGPL, not GPL) and the build is `--onedir`, so the bundled Qt libraries stay replaceable.

For commercial licensing, open a [GitHub issue](https://github.com/JDE-Projects/Simple-SFTP-Audit-Tool/issues) with the title "Commercial License Inquiry".
