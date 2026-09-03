"""Tests for _checklist: proving the SHA-1 host-key and weak-KEX checklist
items are read from ssh-audit's own notes rather than a hardcoded short-name
list (the bug this reworks: ssh-rsa-cert-v01@openssh.com and
gss-gex-sha1-... carry a SHA-1 fail note but were missed by the old lists).
"""
import os

import simple_sftp_audit_tool as app

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return f.read()


def _status_for(checklist, needle):
    for item in checklist:
        if needle in item["text"]:
            return item["status"]
    raise AssertionError(f"no checklist item containing {needle!r}")


def test_sha1_host_key_and_weak_kex_flagged_bad_for_regression_fixture():
    parsed = app._parse_json(_load("ssh2_fail.json"))
    assert parsed is not None
    checklist = app._checklist(parsed)
    assert _status_for(checklist, "SHA-1 host key signatures") == "bad"
    assert _status_for(checklist, "weak SHA-1 key exchange") == "bad"


def test_sha1_host_key_and_weak_kex_good_for_clean_server():
    parsed = app._parse_json(_load("ssh2_warn.json"))
    assert parsed is not None
    checklist = app._checklist(parsed)
    assert _status_for(checklist, "No SHA-1 host key signature") == "good"
    assert _status_for(checklist, "No weak SHA-1 key exchange") == "good"
