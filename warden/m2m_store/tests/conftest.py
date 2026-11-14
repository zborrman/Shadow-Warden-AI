"""
Shared fixtures for the store-builder tests.

The M1-M5 modules exercise the builder itself - isolation, the category tree,
prices, photos, orders - and were written before plans existed. They create
several stores per tenant and stores in three or five languages, which the
default (free) plan rightly refuses. Rather than thread a grant through every
helper, those modules run with the default pinned to the widest plan.

``test_store_plans.py`` pins it back to the real default, so the limits are
tested against the plan a new seller actually lands on.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _widest_plan_by_default(monkeypatch):
    from warden.m2m_store import plans
    monkeypatch.setattr(plans, "DEFAULT_PLAN", "store_business")
