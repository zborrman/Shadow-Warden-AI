"""Record what the storefront API answers, for the portal's offline audit.

The CI accessibility and Lighthouse audit (`portal/e2e/storefront-audit.mjs`)
runs the built portal against `portal/e2e/mock-gateway.mjs`, which replays the
JSON written here. It is recorded from the real `warden.m2m_store` router, so
it has the shapes the portal will meet in production;
`warden/m2m_store/tests/test_storefront_fixture.py` fails when the router's
answers drift away from the committed file.

    python scripts/storefront_fixture.py            # rewrite the fixture
    python scripts/storefront_fixture.py --check    # exit 1 if it is stale
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "portal" / "e2e" / "fixtures" / "storefront.json"
SLUG = "alpine"


def _env() -> None:
    tmp = tempfile.mkdtemp()
    os.environ.update({
        "M2M_STORE_DB_PATH": os.path.join(tmp, "m2m.db"),
        "WARDEN_DATA_DIR": tmp,
        "REDIS_URL": "memory://",
        "ANTHROPIC_API_KEY": "",
        "ALLOW_UNAUTHENTICATED": "true",
        "WARDEN_API_KEY": "",
        "PORTAL_JWT_SECRET": "fixture-secret-fixture-secret-0123456789",
    })
    # A throwaway key: the recorded request's contact details are sealed with it
    # and never leave this process.
    from cryptography.fernet import Fernet
    os.environ["VAULT_MASTER_KEY"] = Fernet.generate_key().decode()


class _MemoryS3:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def head_bucket(self, **kw: Any) -> dict:
        return {}

    def put_object(self, **kw: Any) -> None:
        self.objects[kw["Key"]] = kw["Body"]

    def get_object(self, **kw: Any) -> dict:
        return {"Body": io.BytesIO(self.objects[kw["Key"]])}

    def delete_object(self, **kw: Any) -> None:
        self.objects.pop(kw["Key"], None)


def record() -> dict[str, Any]:
    """Seed one store through the owner routes and capture the public answers."""
    sys.path.insert(0, str(ROOT))
    _env()
    import warden.storage.s3 as s3
    s3.object_client = _MemoryS3  # type: ignore[assignment]

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from PIL import Image

    from warden.limiter import limiter
    from warden.m2m_store.api import router
    from warden.portal_router import _issue_access_token

    app = FastAPI()
    app.state.limiter = limiter
    app.include_router(router)
    c = TestClient(app)
    owner = {"Authorization": f"Bearer {_issue_access_token('u-fixture', 'tenant-fixture', 'owner')}"}
    api = "/m2m-store"

    def ok(r: Any) -> Any:
        assert r.status_code < 300, f"{r.request.method} {r.request.url}: {r.status_code} {r.text}"
        return r.json() if r.content else None

    def png(rgb: tuple[int, int, int]) -> bytes:
        b = io.BytesIO()
        Image.new("RGB", (64, 64), rgb).save(b, "PNG")
        return b.getvalue()

    store = ok(c.post(f"{api}/stores", headers=owner, json={
        "slug": SLUG, "name": "Alpine Pantry", "description": "Cheese, honey and tea from the Alps.",
        "default_currency": "EUR", "currencies": ["EUR", "USD", "CHF"],
        "locales": ["en", "de", "fr", "it", "es"]}))
    sid = store["id"]
    cheese = ok(c.post(f"{api}/stores/{sid}/categories", headers=owner,
                       json={"slug": "cheese", "name": "Cheese", "parent_id": ""}))
    hard = ok(c.post(f"{api}/stores/{sid}/categories", headers=owner,
                     json={"slug": "hard", "name": "Hard cheese", "parent_id": cheese["id"]}))
    tea = ok(c.post(f"{api}/stores/{sid}/categories", headers=owner,
                    json={"slug": "tea", "name": "Tea", "parent_id": ""}))

    def product(name: str, cat: str, usd: int, eur: int, stock: int, unit: str,
                de: str, rgb: tuple[int, int, int]) -> str:
        p = ok(c.post(f"{api}/products", headers=owner, json={
            "store_id": sid, "category_id": cat, "name": name,
            "description": f"{name}, made in the Alps.", "price_minor": usd,
            "stock": stock, "unit": unit, "active": True}))
        ok(c.put(f"{api}/products/{p['id']}/prices", headers=owner, json=[
            {"currency": "USD", "amount_minor": usd}, {"currency": "EUR", "amount_minor": eur}]))
        ok(c.put(f"{api}/products/{p['id']}/translations/de", headers=owner,
                 json={"name": de, "description": f"{de} aus den Alpen."}))
        ok(c.post(f"{api}/products/{p['id']}/images", headers=owner | {"Content-Type": "image/png"},
                  content=png(rgb)))
        return str(p["id"])

    gruyere = product("Gruyère AOP", hard["id"], 3490, 3250, 12, "kg", "Greyerzer AOP", (200, 160, 60))
    product("Alpine herb tea", tea["id"], 990, 920, 40, "piece", "Alpenkräutertee", (90, 150, 70))
    product("Mountain honey", cheese["id"], 1490, 1390, 0, "jar", "Bergblütenhonig", (220, 170, 40))
    for zone in (
        {"name": "DACH", "countries": ["DE", "AT", "CH"], "currency": "EUR", "rate_minor": 690,
         "free_over_minor": 10000, "duty_estimate_bps": 0, "min_days": 2, "max_days": 5},
        {"name": "World", "countries": ["*"], "currency": "EUR", "rate_minor": 2490,
         "free_over_minor": None, "duty_estimate_bps": 800, "min_days": 7, "max_days": 21},
    ):
        ok(c.post(f"{api}/stores/{sid}/shipping-zones", headers=owner, json=zone))

    public = f"{api}/storefront/{SLUG}"
    feed = ok(c.get(f"{public}/catalog/ucp"))
    quote = ok(c.get(f"{public}/shipping/quote",
                     params={"country": "DE", "currency": "EUR", "subtotal_minor": 6500}))
    placed = ok(c.post(f"{public}/order-requests", json={
        "items": [{"product_id": gruyere, "qty": 2}], "currency": "EUR", "country": "DE",
        "contact": {"name": "Fixture Buyer", "email": "buyer@example.org",
                    "address_line1": "1 Example Street", "city": "Berlin"},
        "note": "", "locale": "en", "timezone": "Europe/Berlin"}))
    placed.pop("buyer_token")
    return {
        "_comment": "Recorded by scripts/storefront_fixture.py from the real m2m_store router. Do not edit by hand.",
        "slug": SLUG,
        "store": ok(c.get(public)),
        "feed": feed,
        "quote": quote,
        "order_request": placed,
    }


def shape(v: Any) -> Any:
    """Keys and JSON types only: ids, times and amounts change on every recording."""
    if isinstance(v, dict):
        return {k: shape(x) for k, x in sorted(v.items()) if k != "_comment"}
    if isinstance(v, list):
        return [shape(v[0])] if v else []
    return type(v).__name__


def main() -> int:
    data = record()
    if "--check" in sys.argv:
        committed = json.loads(FIXTURE.read_text(encoding="utf-8"))
        if shape(committed) != shape(data):
            print(f"{FIXTURE} is stale: run python scripts/storefront_fixture.py", file=sys.stderr)
            return 1
        return 0
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {FIXTURE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
