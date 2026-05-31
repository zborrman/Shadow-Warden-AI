"""
warden/m2m_store/tests/test_m2m_store.py
─────────────────────────────────────────
M2M Commerce Store — 16 tests.

Uses SQLite in-memory paths and ENV=development for FIDO2 bypass.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("M2M_STORE_DB_PATH", "/tmp/m2m_test_suite.db")
os.environ.setdefault("ENV", "development")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")  # skip LLM explanation


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_db(tmp_path):
    """Fresh DB for every test."""
    db = str(tmp_path / "m2m.db")
    os.environ["M2M_STORE_DB_PATH"] = db
    # Reset module-level singletons
    from warden.m2m_store import catalog as cat_mod
    from warden.m2m_store import inventory as inv_mod
    from warden.m2m_store import store_agent as agent_mod
    inv_mod._inventory = inv_mod.InventoryManager()
    cat_mod._catalog = cat_mod.AICatalog()
    agent_mod._agent = agent_mod.StoreAgent()
    yield
    if os.path.exists(db):
        os.remove(db)


def _seed_product(name="Test Product", price=10.0, stock=50, category="test"):
    from warden.m2m_store.catalog import get_catalog
    from warden.m2m_store.models import Product
    return get_catalog().add_product(Product(
        name=name, description=f"A {name}", category=category,
        price_base=price, stock=stock,
    ))


# ── 1. Product / catalog ──────────────────────────────────────────────────────

def test_add_and_get_product():
    p = _seed_product()
    from warden.m2m_store.catalog import get_catalog
    retrieved = get_catalog().get_product(p.id)
    assert retrieved is not None
    assert retrieved.name == "Test Product"
    assert retrieved.available == 50


def test_search_by_query():
    _seed_product("Widget A")
    _seed_product("Gadget B")
    from warden.m2m_store.catalog import get_catalog
    results = get_catalog().search("Widget")
    assert len(results) == 1
    assert results[0].name == "Widget A"


def test_search_by_category():
    _seed_product("Security Scan", category="security")
    _seed_product("API Token", category="auth")
    from warden.m2m_store.catalog import get_catalog
    sec = get_catalog().list_by_category("security")
    assert all(p.category == "security" for p in sec)
    assert len(sec) == 1


def test_ucp_catalog_format():
    _seed_product("UCP Item", price=5.0)
    from warden.m2m_store.catalog import get_catalog
    ucp = get_catalog().to_ucp_catalog()
    assert ucp["version"] == "1.0"
    assert ucp["count"] >= 1
    assert all("price" in item for item in ucp["products"])


# ── 2. Offer generation ───────────────────────────────────────────────────────

def test_generate_offer_basic():
    p = _seed_product(price=100.0, stock=10)
    from warden.m2m_store.store_agent import get_agent
    offer = get_agent().generate_offer("agent-1", p.id, qty=2, tenant_id="t1")
    assert offer is not None
    assert offer.price_final > 0
    assert offer.qty == 2


def test_offer_dynamic_price_low_stock():
    """Low stock should push demand factor up → higher price."""
    p = _seed_product(price=100.0, stock=2)
    from warden.m2m_store.store_agent import get_agent
    offer = get_agent().generate_offer("agent-1", p.id, qty=1, tenant_id="t1")
    assert offer is not None
    # demand factor ≥ 1.0 when stock is critically low
    assert offer.price_final >= 100.0


def test_offer_returns_none_when_out_of_stock():
    p = _seed_product(stock=0)
    from warden.m2m_store.store_agent import get_agent
    offer = get_agent().generate_offer("agent-1", p.id, qty=1, tenant_id="t1")
    assert offer is None


def test_offer_returns_none_for_unknown_product():
    from warden.m2m_store.store_agent import get_agent
    offer = get_agent().generate_offer("agent-1", "nonexistent-id", qty=1, tenant_id="t1")
    assert offer is None


# ── 3. Reservation ────────────────────────────────────────────────────────────

def test_reservation_reduces_available():
    p = _seed_product(stock=10)
    from warden.m2m_store.catalog import get_catalog
    from warden.m2m_store.store_agent import get_agent
    offer = get_agent().generate_offer("agent-1", p.id, qty=3, tenant_id="t1")
    offer = get_agent().hold_reservation(offer, ttl_seconds=45)
    assert offer.reservation_id
    updated = get_catalog().get_product(p.id)
    assert updated.available == 7  # 10 - 3 reserved


def test_reservation_release():
    p = _seed_product(stock=5)
    from warden.m2m_store.catalog import get_catalog
    from warden.m2m_store.inventory import get_inventory
    from warden.m2m_store.store_agent import get_agent
    offer = get_agent().generate_offer("agent-1", p.id, qty=2, tenant_id="t1")
    offer = get_agent().hold_reservation(offer, ttl_seconds=45)
    assert offer.reservation_id
    released = get_inventory().release(offer.reservation_id)
    assert released is True
    updated = get_catalog().get_product(p.id)
    assert updated.available == 5  # fully restored


# ── 4. Security ───────────────────────────────────────────────────────────────

def test_prompt_injection_blocked_product_id():
    from warden.m2m_store.security import PromptInjectionError, validate_offer_request
    with pytest.raises(PromptInjectionError):
        validate_offer_request("DROP TABLE products; --", "agent-1")


def test_prompt_injection_blocked_template():
    from warden.m2m_store.security import PromptInjectionError, validate_offer_request
    with pytest.raises(PromptInjectionError):
        validate_offer_request("{{system_prompt}}", "agent-1")


def test_valid_request_passes_validation():
    from warden.m2m_store.security import validate_offer_request
    validate_offer_request("prod-abc-123", "agent-xyz")  # must not raise


def test_rate_limit_allows_under_threshold():
    from warden.m2m_store.security import check_rate_limit
    for _ in range(5):
        assert check_rate_limit("agent-rl-test") is True


def test_fido2_dev_mode_bypass():
    from warden.m2m_store.security import validate_fido2_token
    result = validate_fido2_token("any-token", "agent-1")
    assert result["valid"] is True  # dev mode bypass


# ── 5. Budget guardian integration ───────────────────────────────────────────

def test_budget_check_fail_open():
    """Budget check must fail-open — commerce never blocked by infra failures."""
    p = _seed_product(price=999.0, stock=5)
    from warden.m2m_store.store_agent import get_agent
    offer = get_agent().generate_offer("agent-1", p.id, qty=1, tenant_id="t_no_settings")
    # Should produce an offer even without budget settings configured
    assert offer is not None


# ── 6. Inventory & order persistence ─────────────────────────────────────────

def test_order_save_and_retrieve():
    from datetime import UTC, datetime

    from warden.m2m_store.inventory import get_inventory
    from warden.m2m_store.models import Order
    order = Order(
        id="ord-test-001", agent_id="agent-1", offer_id="off-1",
        product_id="prod-1", mandate_id="mand-1", qty=1, total=50.0,
        status="PAID", created_at=datetime.now(UTC).isoformat(),
    )
    inv = get_inventory()
    inv.save_order(order)
    retrieved = inv.get_order("ord-test-001")
    assert retrieved is not None
    assert retrieved.status == "PAID"
    assert retrieved.total == 50.0


def test_order_history_filter_by_agent():
    from datetime import UTC, datetime

    from warden.m2m_store.inventory import get_inventory
    from warden.m2m_store.models import Order
    inv = get_inventory()
    for i, agent in enumerate(["agent-A", "agent-B", "agent-A"]):
        inv.save_order(Order(
            id=f"ord-{i}", agent_id=agent, offer_id=f"off-{i}",
            product_id="prod-1", mandate_id="mand-1", qty=1, total=10.0,
            status="PAID", created_at=datetime.now(UTC).isoformat(),
        ))
    history_a = inv.list_orders(agent_id="agent-A")
    assert len(history_a) == 2
    history_b = inv.list_orders(agent_id="agent-B")
    assert len(history_b) == 1
