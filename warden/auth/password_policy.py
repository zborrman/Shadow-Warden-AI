"""Strong-password rule for portal accounts.

The portal's sign-up, password reset and password change all pass through
``require_strong()``. The browser shows the same rules as the person types
(``portal/src/lib/password.ts``), but only this check is binding: a request
sent without the page must meet it too.

Signing in is deliberately NOT checked, so an account made under the old
8-character minimum can still sign in and then change its password.
"""
from __future__ import annotations

import re

from fastapi import HTTPException

MIN_LENGTH = 12
# bcrypt reads only the first 72 bytes; a longer password would silently
# match any password sharing that prefix.
MAX_BYTES = 72

# Words that turn up in every leaked-password list, plus our own names.
COMMON = (
    "password", "passw0rd", "qwerty", "123456", "letmein", "welcome",
    "iloveyou", "admin", "shadowwarden", "warden", "amazon",
)


def problems(password: str, email: str = "") -> list[str]:
    """Every rule the password breaks, in the order the page lists them."""
    out: list[str] = []
    if len(password) < MIN_LENGTH:
        out.append(f"at least {MIN_LENGTH} characters")
    if len(password.encode()) > MAX_BYTES:
        out.append(f"at most {MAX_BYTES} bytes")
    if not re.search(r"[A-Z]", password):
        out.append("an upper-case letter")
    if not re.search(r"[a-z]", password):
        out.append("a lower-case letter")
    if not re.search(r"[0-9]", password):
        out.append("a number")
    if not re.search(r"[^A-Za-z0-9]", password):
        out.append("a symbol")
    low = password.lower()
    local = email.split("@", 1)[0].lower()
    if (len(local) >= 3 and local in low) or any(w in low for w in COMMON):
        out.append("no email name or common word")
    return out


def require_strong(password: str, email: str = "") -> None:
    """Raise 422 with one readable sentence when the password is weak."""
    bad = problems(password, email)
    if bad:
        raise HTTPException(
            status_code=422,
            detail="Choose a stronger password. It needs " + ", ".join(bad) + ".",
        )
