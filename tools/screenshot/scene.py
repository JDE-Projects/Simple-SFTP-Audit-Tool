#!/usr/bin/env python3
"""What the README screenshot shows: a completed audit of a well-configured
but not perfect SSH/SFTP server.

None of this is real. The host, IP, banner, algorithms, and fingerprints are
all invented to look like a genuine audit without naming a real machine. The
shape matches the "ok" dict returned by SftpAuditApi.run_audit() in
simple_sftp_audit_tool.py: ok, host, port, grade, grade_color, counts,
software, os, compression, security_issues, checklist, sections, security
recommendations, fingerprints, rate_test.

The version shown in the image always comes from simple_sftp_audit_tool.py at
run time, never from here, so this fixture holds no version number.
"""

HOST = "fileserver.prod.internal"
PORT = 22

SOFTWARE = "OpenSSH 9.7"
OS = "Linux (Ubuntu, guess)"
COMPRESSION = ["none", "zlib@openssh.com"]

# Algorithm sections. Two warns (a SHA-2 DH group and a MAC offered without
# its encrypt-then-mac variant) keep the breakdown from reading as all-green,
# while everything else is a modern, secure choice. Zero fails, two warns
# grades out to "A" per _grade() in simple_sftp_audit_tool.py.
SECTIONS = {
    "kex": [
        {"name": "curve25519-sha256", "status": "good", "reason": "", "key_size": None},
        {"name": "curve25519-sha256@libssh.org", "status": "good", "reason": "", "key_size": None},
        {"name": "ecdh-sha2-nistp256", "status": "good", "reason": "", "key_size": None},
        {"name": "diffie-hellman-group14-sha256", "status": "warn",
         "reason": "SHA-2 based DH group; elliptic-curve exchanges are preferred", "key_size": 2048},
    ],
    "key": [
        {"name": "ssh-ed25519", "status": "good", "reason": "", "key_size": 256},
        {"name": "rsa-sha2-512", "status": "good", "reason": "", "key_size": 3072},
        {"name": "ecdsa-sha2-nistp256", "status": "good", "reason": "", "key_size": 256},
    ],
    "enc": [
        {"name": "chacha20-poly1305@openssh.com", "status": "good", "reason": "", "key_size": 256},
        {"name": "aes256-gcm@openssh.com", "status": "good", "reason": "", "key_size": 256},
        {"name": "aes128-ctr", "status": "good", "reason": "", "key_size": 128},
    ],
    "mac": [
        {"name": "hmac-sha2-256-etm@openssh.com", "status": "good", "reason": "", "key_size": None},
        {"name": "hmac-sha2-512", "status": "warn",
         "reason": "no encrypt-then-mac (ETM) variant offered alongside it", "key_size": None},
    ],
}

CHECKLIST = [
    {"status": "good", "text": "No SHA-1 signature algorithms (ssh-rsa not supported)"},
    {"status": "good", "text": "Supports modern key exchange (Curve25519)"},
    {"status": "good", "text": "No weak key exchange algorithms"},
    {"status": "good", "text": "Strong AEAD encryption ciphers offered (chacha20-poly1305, aes256-gcm)"},
    {"status": "warn", "text": "hmac-sha2-512 offered without its encrypt-then-mac (ETM) variant"},
    {"status": "warn", "text": "diffie-hellman-group14-sha256 still offered alongside Curve25519"},
]

SECURITY_ISSUES = [
    "hmac-sha2-512 is offered without an encrypt-then-mac (ETM) counterpart.",
]

RECOMMENDATIONS = [
    "Prefer hmac-sha2-512-etm@openssh.com over hmac-sha2-512 where client support allows.",
    "Consider retiring diffie-hellman-group14-sha256 now that Curve25519 key exchange is supported.",
]

FINGERPRINTS = [
    "ssh-ed25519: SHA256:k8Qm2vT4pXwYzB7nR1dE9sJhC6uL3fA0oV5iN2gZ8xQ",
    "rsa-sha2-512: MD5:3e:8a:1c:9f:52:d6:07:44:bb:2a:c1:95:e0:6f:78:04",
]

COUNTS = {"fails": 0, "warns": 2, "goods": 10}
GRADE = "A"
GRADE_COLOR = "#4dd6c1"
RATE_TEST = True


def result(version_unused=None):
    """Build the sample run_audit() success dict. Takes no version: the
    version bar is set separately from APP_VERSION, never from here."""
    return {
        "ok": True,
        "host": HOST,
        "port": PORT,
        "grade": GRADE,
        "grade_color": GRADE_COLOR,
        "counts": COUNTS,
        "software": SOFTWARE,
        "os": OS,
        "compression": COMPRESSION,
        "security_issues": SECURITY_ISSUES,
        "checklist": CHECKLIST,
        "sections": SECTIONS,
        "recommendations": RECOMMENDATIONS,
        "fingerprints": FINGERPRINTS,
        "rate_test": RATE_TEST,
    }
