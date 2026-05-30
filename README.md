# Simple SFTP Audit Tool

A standalone desktop tool that scans an SFTP/SSH server and shows its security posture at a glance. Enter a host and port, click **Run Audit**, and get an overall A-F grade, server details, and a color-coded breakdown of every algorithm the server offers. It wraps the well-known [ssh-audit](https://github.com/jtesta/ssh-audit) engine in a clean dark-themed window.

Built by [JDE-Projects](https://github.com/JDE-Projects).

## Highlights

- **At-a-glance grade.** Every scan returns an overall A+ to F grade plus a count of failures, warnings, and secure items.
- **Plain-language security checklist.** Instead of just listing algorithms, it calls out the things that matter: SHA-1 signatures, weak key exchange, CBC ciphers, RC4/3DES, MD5 MACs, and whether modern options (Curve25519, Ed25519, AEAD, Encrypt-then-MAC) are present.
- **Organized by category.** Key exchange, host key, encryption, and MAC algorithms are grouped, each with red/yellow/green status and key sizes where reported.
- **Server fingerprint and details.** Software banner, detected OS, compression, and host key fingerprints.
- **One-click report.** Copy a full text report to the clipboard for tickets or records. Nothing is written to disk.

## How it works

- The audit engine is [ssh-audit](https://github.com/jtesta/ssh-audit), run in-process and its output parsed into the visual layout.
- The window is built with Python's standard `tkinter`, so there are no heavy UI dependencies.
- The security checklist logic lives in `simple_sftp_audit.py`, so it stays accurate even if the underlying ssh-audit database lags behind on the big, stable verdicts.

## Download and run

Grab the latest `SimpleSFTPAuditTool.exe` from the [Releases](../../releases) page and double-click it. No Python or setup required. Windows only.

Because it is unsigned, Windows SmartScreen may warn about an unknown publisher the first time. Click **More info > Run anyway**.

## Build from source (optional)

If you would rather run or build it yourself, you need:

- **Python 3** on the machine's PATH.
- The `ssh-audit` package (to run from source) and `pyinstaller` (to build the exe).

```
pip install ssh-audit pyinstaller
```

Keep `simple_sftp_audit.py` and `simple_sftp_audit.ico` together (the app loads the icon next to itself). Then either:

- **Run from source:** `python simple_sftp_audit.py`
- **Build the .exe:** double-click `build_simple_sftp_audit.bat`, which uses PyInstaller to produce `dist\SimpleSFTPAuditTool.exe`.

The build script pulls ssh-audit from the GitHub **master** branch rather than the older PyPI release, so the bundled engine has the most current algorithm coverage. That step needs [Git](https://git-scm.com) installed on the build machine (not on end users).

## Using it

1. Type the server's hostname or IP in **Host/IP**, and the port in **Port** (default SFTP/SSH is 22). You can also paste `host:port` into the host box and it splits automatically.
2. Click **Run Audit** (or press Enter).
3. Read the grade and summary at the top, then scroll for the security checklist, advisories, and per-category algorithm lists. Green is good, yellow is a warning, red is a failure.
4. Click **Copy Report to Clipboard** to save a plain-text version. **Clear** resets the view.

## What it checks

The tool reports on the server's:

- **Key exchange algorithms** (flags SHA-1 based Diffie-Hellman, credits Curve25519)
- **Host key algorithms** (flags `ssh-rsa`/SHA-1, credits Ed25519)
- **Encryption ciphers** (flags CBC mode, RC4/arcfour, 3DES; credits ChaCha20-Poly1305 and AES-GCM)
- **Message authentication codes** (flags MD5-based MACs; credits Encrypt-then-MAC)
- **Server information** (software banner, OS guess, compression, host key fingerprints)

A few things worth knowing:

- The grade is derived from the count of failures and warnings across the four algorithm categories.
- Post-quantum / "Harvest Now, Decrypt Later" notices from newer ssh-audit builds show as warnings, not failures. A modern server without post-quantum hybrids is not broken, just not future-proofed yet.
- The scan is unauthenticated. It inspects what the server advertises during the handshake; it does not log in.

## Security and privacy

- Nothing is written to disk. There is no config or data file. The only output is the on-screen result and the report you choose to copy to the clipboard.
- No credentials are used or stored. The tool never logs into the server.
- Only scan servers you own or are authorized to test.

## A note on how this was built

This project was built with AI assistance. The design decisions, feature direction, and real-world testing were directed by me. The code was written and revised with an AI assistant against that direction. Treat it like any community tool, review and test it before relying on it.

## License

Released under the [MIT License](LICENSE). You are free to use, modify, and distribute it; keep the copyright notice, and it comes with no warranty.
