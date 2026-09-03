"""Tests for _parse_json: parsing ssh-audit's `-j` JSON output into the
structured dict the rest of the app consumes. Fixtures under tests/fixtures/
are read as raw text and passed straight into _parse_json, the same entry
point run_audit uses.
"""
import os

import simple_sftp_audit_tool as app

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return f.read()


def test_ssh2_full_maps_software_compression_and_algorithms():
    parsed = app._parse_json(_load("ssh2_full.json"))
    assert parsed is not None
    assert parsed["software"] == "paramiko_5.0.0"
    assert parsed["compression"] == ["none"]

    kex_by_name = {a["name"]: a for a in parsed["kex"]}
    assert kex_by_name["curve25519-sha256@libssh.org"]["status"] == "warn"
    assert kex_by_name["ecdh-sha2-nistp256"]["status"] == "fail"
    assert "backdoored" in kex_by_name["ecdh-sha2-nistp256"]["reason"]
    assert kex_by_name["kex-strict-s-v00@openssh.com"]["status"] == "good"

    key_by_name = {a["name"]: a for a in parsed["key"]}
    assert key_by_name["rsa-sha2-512"]["key_size"] == "2048"
    assert key_by_name["rsa-sha2-512"]["status"] == "warn"

    enc_by_name = {a["name"]: a for a in parsed["enc"]}
    assert enc_by_name["3des-cbc"]["status"] == "fail"
    assert enc_by_name["aes128-ctr"]["status"] == "good"

    mac_by_name = {a["name"]: a for a in parsed["mac"]}
    assert mac_by_name["hmac-sha1"]["status"] == "fail"

    assert len(parsed["fingerprints"]) == 2
    assert parsed["fingerprints"][0].startswith("ssh-rsa (SHA256):")


def test_ssh1_derives_v1_security_issue():
    parsed = app._parse_json(_load("ssh1.json"))
    assert parsed is not None
    assert any("SSH v1 enabled" in issue for issue in parsed["security_issues"])


def test_no_json_returns_none():
    assert app._parse_json(_load("no_json.txt")) is None


def test_banner_only_yields_empty_algorithm_sections():
    parsed = app._parse_json(_load("banner_only.json"))
    assert parsed is not None
    assert parsed["software"] == "libssh_0.9"
    for section in ("kex", "key", "enc", "mac"):
        assert parsed[section] == []


def test_recommendations_flatten_empty_dict_without_crashing():
    parsed = app._parse_json(_load("ssh2_full.json"))
    assert parsed is not None
    assert parsed["recommendations"] == []


def test_flatten_recommendations_builds_readable_strings():
    recommendations = {
        "critical": {
            "del": {"kex": [{"name": "diffie-hellman-group1-sha1", "notes": "insecure"}]},
            "add": {"key": [{"name": "ssh-ed25519", "notes": ""}]},
        },
        "warning": {
            "chg": {"enc": [{"name": "aes256-cbc", "notes": "prefer AEAD"}]},
        },
    }
    flat = app._flatten_recommendations(recommendations)
    assert "Remove diffie-hellman-group1-sha1 (insecure)" in flat
    assert "Add ssh-ed25519" in flat
    assert "Change aes256-cbc (prefer AEAD)" in flat
