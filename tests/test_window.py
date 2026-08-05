"""
Tests for the Win32 window-lookup helper in simple_sftp_audit_tool.py.

Real window enumeration needs a live desktop window and isn't something a
unit test can meaningfully exercise, so this only covers the safety contract
both _save_geometry and _restore_geometry depend on: a failure anywhere in
the underlying Win32 calls must come back as None, not raise.
"""

import simple_sftp_audit_tool as app


# ─────────────────────────────────────────────────────────────
#  _own_window_handle
# ─────────────────────────────────────────────────────────────
def test_own_window_handle_returns_none_on_win32_failure(monkeypatch):
    class _RaisingWindll:
        def __getattr__(self, name):
            raise OSError("simulated user32 access failure")

    monkeypatch.setattr(app.ctypes, "windll", _RaisingWindll())

    assert app._own_window_handle("Simple SFTP Audit Tool") is None
