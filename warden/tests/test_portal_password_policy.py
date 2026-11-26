"""Portal accounts take only strong passwords, checked on the server.

The page shows the same rules as the person types, but a request sent without
the page must meet them too: sign-up, reset and change all call
``password_policy.require_strong``. Signing in is not checked, so an account
made under the old 8-character minimum can still get in and change it.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from warden.auth import password_policy as pp


@pytest.mark.parametrize("pw", ["Correct-Horse-9", "Tr4ck!ng-Numbers", "Ünïcode-Pass-7x"])
def test_strong_passwords_pass(pw):
    assert pp.problems(pw, "seller@example.com") == []


@pytest.mark.parametrize(("pw", "missing"), [
    ("Short-1a", "at least 12 characters"),
    ("lower-case-only-1", "an upper-case letter"),
    ("UPPER-CASE-ONLY-1", "a lower-case letter"),
    ("No-Numbers-Here!", "a number"),
    ("NoSymbolsHere123", "a symbol"),
    ("My-Password-2026", "no email name or common word"),
    ("Seller-Shop-2026!", "no email name or common word"),
    ("A1!" + "x" * 80, "at most 72 bytes"),
])
def test_each_rule_is_enforced(pw, missing):
    assert missing in pp.problems(pw, "seller@example.com")


def test_a_weak_password_is_a_422_with_one_sentence():
    with pytest.raises(HTTPException) as e:
        pp.require_strong("password", "a@b.co")
    assert e.value.status_code == 422
    assert isinstance(e.value.detail, str) and e.value.detail.startswith("Choose a stronger password.")


def test_every_handler_that_sets_a_password_checks_it():
    import inspect

    from warden import portal_router as pr
    for fn in (pr.register, pr.reset_password, pr.change_password):
        assert "require_strong(" in inspect.getsource(fn), fn.__name__
    assert "require_strong(" not in inspect.getsource(pr.login)


def test_the_portal_page_lists_the_same_rules():
    from pathlib import Path
    ts = (Path(__file__).resolve().parents[2] / "portal/src/lib/password.ts").read_text(encoding="utf-8")
    assert f"MIN_LENGTH = {pp.MIN_LENGTH}" in ts
    for word in pp.COMMON:
        assert f"'{word}'" in ts, word
