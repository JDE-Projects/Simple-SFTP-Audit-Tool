"""Tests for the tier-ceiling grading model (see blueprint.md): _counts and
_grade turn ssh-audit's raw FAIL_*/WARN_* reason labels into a letter grade.
The worst tier present anywhere sets the ceiling letter; a demerit count
drives a +/- modifier within that letter. Fixtures under tests/fixtures/ are
read as raw text and passed through _parse_json, the same path run_audit uses.
"""
import os

from ssh_audit.ssh2_kexdb import SSH2_KexDB

import simple_sftp_audit_tool as app

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return f.read()


def _grade_for(name):
    parsed = app._parse_json(_load(name))
    assert parsed is not None
    counts = app._counts(parsed)
    grade, color = app._grade(counts, ssh_v1=parsed["ssh_v1"])
    return grade, color, counts


def _alg(name, fail_labels=None, warn_labels=None):
    """Build a parsed-algorithm dict directly, bypassing JSON, for tests that
    only need to exercise the scoring functions."""
    fail_labels = fail_labels or []
    warn_labels = warn_labels or []
    status = "fail" if fail_labels else "warn" if warn_labels else "good"
    return {
        "name": name, "status": status, "reason": "; ".join(fail_labels + warn_labels),
        "key_size": None, "fail_labels": list(fail_labels), "warn_labels": list(warn_labels),
    }


def _parsed(kex=None, key=None, enc=None, mac=None, ssh_v1=False):
    return {
        "kex": kex or [], "key": key or [], "enc": enc or [], "mac": mac or [],
        "ssh_v1": ssh_v1,
    }


# --------------------------------------------------------------------------- #
# 1. Ceiling boundaries.
# --------------------------------------------------------------------------- #

def test_tier0_label_ceils_at_f():
    parsed = _parsed(enc=[_alg("3des-cbc", fail_labels=[SSH2_KexDB.FAIL_3DES])])
    counts = app._counts(parsed)
    grade, _ = app._grade(counts, ssh_v1=False)
    assert grade == "F"


def test_tier1_label_ceils_at_c():
    parsed = _parsed(key=[_alg("ssh-rsa", fail_labels=[SSH2_KexDB.FAIL_SHA1])])
    counts = app._counts(parsed)
    grade, _ = app._grade(counts, ssh_v1=False)
    assert grade.startswith("C")


def test_tier2_label_ceils_at_b():
    parsed = _parsed(enc=[_alg("aes256-cbc", warn_labels=[SSH2_KexDB.WARN_CIPHER_MODE])])
    counts = app._counts(parsed)
    grade, _ = app._grade(counts, ssh_v1=False)
    assert grade.startswith("B")


def test_no_graded_labels_ceils_at_a():
    parsed = _parsed(kex=[_alg("curve25519-sha256@libssh.org")])
    counts = app._counts(parsed)
    grade, _ = app._grade(counts, ssh_v1=False)
    assert grade.startswith("A")


# --------------------------------------------------------------------------- #
# 2. Non-dilution: one bad algorithm among many good ones is not diluted.
# --------------------------------------------------------------------------- #

def test_single_tier0_finding_among_many_goods_still_grades_f():
    grade, _, counts = _grade_for("ssh2_single_rc4.json")
    assert grade == "F"
    assert counts["goods"] >= 5


def test_single_tier1_finding_among_many_goods_still_grades_c():
    grade, _, counts = _grade_for("ssh2_single_sha1_hostkey.json")
    assert grade.startswith("C")
    assert counts["goods"] >= 2


# --------------------------------------------------------------------------- #
# 3. The NIST-ECDSA "weak RNG" trap: FAIL_NSA_BACKDOORED_CURVE and
# WARN_RNDSIG_KEY set no tier ceiling, but a NIST P-curve does soft-cap an
# otherwise A+/A grade at A-.
# --------------------------------------------------------------------------- #

def test_nist_ecdsa_weak_rng_and_backdoored_curve_labels_soft_cap_at_a_minus():
    grade, _, counts = _grade_for("ssh2_ecdsa_trap.json")
    assert grade == "A-"
    assert counts["nist_curve"] is True


def test_secp256k1_weak_rng_alone_does_not_trigger_soft_cap():
    # WARN_RNDSIG_KEY without FAIL_NSA_BACKDOORED_CURVE (secp256k1 is not a
    # NIST curve) must not soft-cap the grade.
    grade, _, counts = _grade_for("ssh2_secp256k1.json")
    assert grade == "A+"
    assert counts["nist_curve"] is False


def test_nist_curve_does_not_rescue_or_worsen_a_tier2_finding():
    grade, _, counts = _grade_for("ssh2_nist_curve_tier2.json")
    assert grade.startswith("B")
    assert counts["nist_curve"] is True


def test_nist_curve_does_not_rescue_or_worsen_a_tier1_finding():
    grade, _, counts = _grade_for("ssh2_nist_curve_tier1.json")
    assert grade.startswith("C")
    assert counts["nist_curve"] is True


# --------------------------------------------------------------------------- #
# 4. "No post-quantum" is informational, not a deduction.
# --------------------------------------------------------------------------- #

def test_no_post_quantum_warning_does_not_lower_grade():
    grade, _, _ = _grade_for("ssh2_pq_only.json")
    assert grade.startswith("A")


# --------------------------------------------------------------------------- #
# 5. Per-algorithm-worst-tier counting: two labels on one algorithm count once.
# --------------------------------------------------------------------------- #

def test_algorithm_with_two_labels_counts_once_at_its_worst_tier():
    # group1-sha1 carries both FAIL_LOGJAM_ATTACK (tier 0) and FAIL_SHA1 (tier 1).
    parsed = _parsed(kex=[_alg(
        "diffie-hellman-group1-sha1",
        fail_labels=[SSH2_KexDB.FAIL_LOGJAM_ATTACK, SSH2_KexDB.FAIL_SHA1],
    )])
    counts = app._counts(parsed)
    assert counts["fails"] == 1
    assert counts["warns"] == 0
    assert counts["goods"] == 0
    assert counts["worst_tier"] == 0
    # Only the tier-1 demerit counter should not also be incremented for the
    # same algorithm's tier-0 label.
    assert counts["tier1_count"] == 0


# --------------------------------------------------------------------------- #
# 6. Modifier thresholds: calibration cases from blueprint.md.
# --------------------------------------------------------------------------- #

def test_github_style_single_sha1_hostkey_grades_c_plus():
    grade, _, counts = _grade_for("ssh2_single_sha1_hostkey.json")
    assert grade == "C+"
    assert counts["tier1_count"] == 1
    assert counts["tier2_count"] == 0


def test_cerberus_style_pile_of_deprecated_settings_grades_c_minus():
    grade, _, counts = _grade_for("ssh2_cerberus.json")
    assert grade == "C-"
    d = 3 * counts["tier1_count"] + counts["tier2_count"]
    assert d >= 10


def test_clean_modern_server_grades_a_plus():
    grade, _, _ = _grade_for("ssh2_clean.json")
    assert grade == "A+"


# --------------------------------------------------------------------------- #
# 7. Case A coverage guard: every label in ssh-audit's own database must be
#    judged (tiered or explicitly not-graded). If a future ssh-audit release
#    adds or renames a FAIL_*/WARN_* reason, this test goes red.
# --------------------------------------------------------------------------- #

def test_every_master_db_label_is_tiered_or_not_graded():
    judged = set(app._TIER_MAP) | app._NOT_GRADED_LABELS | {app._UNKNOWN_LABEL}
    seen = set()
    for category in SSH2_KexDB.MASTER_DB.values():
        for entry in category.values():
            # Each entry is [versions, fail_notes, warn_notes, (info_notes)].
            fail_notes = entry[1] if len(entry) > 1 else []
            warn_notes = entry[2] if len(entry) > 2 else []
            seen.update(fail_notes)
            seen.update(warn_notes)
    missing = seen - judged
    assert not missing, f"Unjudged ssh-audit reason label(s): {missing}"
    assert len(seen) == 29, f"Expected 29 known reason labels, found {len(seen)}: {seen}"


# --------------------------------------------------------------------------- #
# 8. Case B: FAIL_UNKNOWN is shown as unrecognized, never secure, never a
#    ceiling.
# --------------------------------------------------------------------------- #

def test_unknown_algorithm_is_not_secure_and_does_not_set_ceiling():
    grade, _, counts = _grade_for("ssh2_unknown_algo.json")
    assert grade.startswith("A")
    # 4 known-good algorithms total (kex/key/enc/mac), the 5th (unknown) is
    # counted in none of fails/warns/goods.
    assert counts["fails"] == 0
    assert counts["warns"] == 0
    assert counts["goods"] == 4
