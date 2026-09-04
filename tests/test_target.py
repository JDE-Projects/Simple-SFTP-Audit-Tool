"""Tests for validate_target: the pure-Python check that runs before any
scan, covering port range/format rules and host handling (hostnames, IPv4,
IPv6, bracketed IPv6, and rejected inputs). No network involved.
"""
import simple_sftp_audit_tool as app


def test_port_zero_is_out_of_range():
    r = app.validate_target("example.com", "0")
    assert r["ok"] is False
    assert "between 1 and 65535" in r["error"]

    r = app.validate_target("example.com", 0)
    assert r["ok"] is False
    assert "between 1 and 65535" in r["error"]


def test_port_one_and_max_are_ok():
    r = app.validate_target("example.com", "1")
    assert r["ok"] is True
    assert r["port"] == 1

    r = app.validate_target("example.com", "65535")
    assert r["ok"] is True
    assert r["port"] == 65535


def test_port_above_max_is_out_of_range():
    r = app.validate_target("example.com", "65536")
    assert r["ok"] is False
    assert "between 1 and 65535" in r["error"]


def test_port_negative_is_rejected():
    r = app.validate_target("example.com", "-1")
    assert r["ok"] is False
    assert "port" in r["error"].lower()


def test_port_non_numeric_is_rejected():
    r = app.validate_target("example.com", "abc")
    assert r["ok"] is False
    assert r["error"] == "Port must be a number."


def test_port_with_surrounding_whitespace_is_ok():
    r = app.validate_target("example.com", " 22 ")
    assert r["ok"] is True
    assert r["port"] == 22


def test_hostname_is_valid():
    r = app.validate_target("example.com", 22)
    assert r["ok"] is True
    assert r["family"] == "host"
    assert r["host"] == "example.com"


def test_ipv4_address_is_valid():
    r = app.validate_target("10.0.0.5", 22)
    assert r["ok"] is True
    assert r["family"] == "ipv4"
    assert r["host"] == "10.0.0.5"


def test_bare_ipv6_address_is_valid():
    r = app.validate_target("2001:db8::1", 22)
    assert r["ok"] is True
    assert r["family"] == "ipv6"
    assert r["host"] == "2001:db8::1"


def test_bracketed_ipv6_address_strips_brackets():
    r = app.validate_target("[2001:db8::1]", 22)
    assert r["ok"] is True
    assert r["family"] == "ipv6"
    assert r["host"] == "2001:db8::1"


def test_loopback_ipv6_address_is_valid():
    r = app.validate_target("::1", 22)
    assert r["ok"] is True
    assert r["family"] == "ipv6"


def test_host_starting_with_dash_is_rejected():
    r = app.validate_target("-oProxyCommand=x", 22)
    assert r["ok"] is False
    assert r["error"] == "Host cannot start with a dash."


def test_empty_host_is_rejected():
    r = app.validate_target("", 22)
    assert r["ok"] is False
    assert r["error"] == "Please enter a hostname or IP address."


def test_whitespace_only_host_is_rejected():
    r = app.validate_target("   ", 22)
    assert r["ok"] is False
    assert r["error"] == "Please enter a hostname or IP address."


def test_invalid_host_is_rejected():
    r = app.validate_target("not a host!", 22)
    assert r["ok"] is False
    assert r["error"] == "That does not look like a valid hostname or IP address."
