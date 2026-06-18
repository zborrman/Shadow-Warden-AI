"""
warden/middleware/region.py  (SC-03)
─────────────────────────────────────
X-Region middleware — tags every response with the serving region and
reads the client-preferred region from the request header.

Headers
-------
Request:  X-Region-Prefer: eu | us | ap   (optional client hint)
Response: X-Region: eu                    (always set by middleware)
          X-Region-Latency-Ms: 12         (processing time, optional)

The WARDEN_REGION env var (default "eu") identifies this instance.
The sovereign router (warden/sovereign/router.py) uses X-Region-Prefer
to steer traffic at the gateway layer.
"""
from __future__ import annotations

import os
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_REGION = os.getenv("WARDEN_REGION", "eu")
_VALID_REGIONS = {"eu", "us", "ap", "uk", "sg", "au"}


class RegionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        t0       = time.monotonic()
        response = await call_next(request)
        elapsed  = int((time.monotonic() - t0) * 1000)

        response.headers["X-Region"]            = _REGION
        response.headers["X-Region-Latency-Ms"] = str(elapsed)

        prefer = request.headers.get("X-Region-Prefer", "").lower()
        if prefer and prefer in _VALID_REGIONS and prefer != _REGION:
            response.headers["X-Region-Redirect"] = prefer

        return response
