"""
shadow_warden._version_path — where the API version gets attached.

Every path literal in this SDK is unversioned: ``/filter``, ``/tax/calculate``,
``/business-community/commerce/orders``. The gateway still serves all of them,
but since 2026-08-23 it serves them with::

    deprecation: true
    sunset: Mon, 23 Aug 2027 00:00:00 GMT
    link: </v1/…>; rel="successor-version"

So the SDK published as the platform's front door was calling the surface the
same release declared deprecated. Not broken — dated, silently, with a clock
already running.

The join happens **here** rather than at the ~15 call sites, for the same reason
the escrow's ``tradeId`` is injected in one place: a path literal is easy to add
and easy to add unversioned, and nothing about writing a new method reminds you.
One seam means a new method cannot ship on the legacy surface by omission.

``api_version=None`` addresses the unversioned surface deliberately — for a
gateway older than the alias middleware, which is the one case where reaching
the deprecated paths is correct rather than accidental.
"""
from __future__ import annotations

#: The version this SDK speaks. Bump only alongside a gateway that serves it.
API_VERSION = "v1"


def versioned_base(gateway_url: str, api_version: str | None = API_VERSION) -> str:
    """Return the base URL every request should be built from.

    Idempotent: a ``gateway_url`` that already ends in the version segment is
    returned unchanged, so a caller who versioned their own base URL does not
    end up requesting ``/v1/v1/filter``.
    """
    base = (gateway_url or "").rstrip("/")
    if not api_version:
        return base
    seg = api_version.strip("/")
    if not seg or base.endswith("/" + seg):
        return base
    return base + "/" + seg
