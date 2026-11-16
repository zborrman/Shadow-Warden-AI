"""
The anonymous metrics stream ends, and there is a ceiling on how many run.

`GET /marketplace/analytics/stream` is public by design (aggregate numbers) and
was unbounded: a connection lived as long as the client held it and nothing
limited their number, each holding a task that recomputes the metrics per tick.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

import warden.marketplace.api as api


class _Request:
    def __init__(self, disconnected: bool = False) -> None:
        self._disconnected = disconnected

    async def is_disconnected(self) -> bool:
        return self._disconnected


async def _drain(resp) -> list[str]:
    out = []
    async for chunk in resp.body_iterator:
        out.append(chunk if isinstance(chunk, str) else chunk.decode())
    return out


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    monkeypatch.setattr(api, "_sse_open_streams", 0)

    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(asyncio, "sleep", _no_sleep)


async def test_a_stream_ends_after_the_event_limit(monkeypatch):
    monkeypatch.setattr(api, "_SSE_MAX_EVENTS", 3)
    with patch("warden.marketplace.analytics.get_live_metrics", AsyncMock(return_value={"n": 1})):
        chunks = await _drain(await api.analytics_stream(_Request()))
    assert len(chunks) == 3
    assert chunks[0].startswith("id: 0\n")
    assert api._sse_open_streams == 0


async def test_a_failing_source_still_reaches_the_end(monkeypatch):
    monkeypatch.setattr(api, "_SSE_MAX_EVENTS", 4)
    boom = AsyncMock(side_effect=RuntimeError("down"))
    with patch("warden.marketplace.analytics.get_live_metrics", boom):
        chunks = await _drain(await api.analytics_stream(_Request()))
    assert chunks == ["event: error\ndata: {}\n\n"] * 4
    assert api._sse_open_streams == 0


async def test_the_slot_is_released_when_the_client_leaves(monkeypatch):
    with patch("warden.marketplace.analytics.get_live_metrics", AsyncMock(return_value={})):
        chunks = await _drain(await api.analytics_stream(_Request(disconnected=True)))
    assert chunks == []
    assert api._sse_open_streams == 0


async def test_a_worker_refuses_streams_past_the_ceiling(monkeypatch):
    monkeypatch.setattr(api, "_sse_open_streams", api._SSE_MAX_STREAMS)
    with pytest.raises(HTTPException) as exc:
        await api.analytics_stream(_Request())
    assert exc.value.status_code == 503
    assert exc.value.headers["Retry-After"] == "30"


async def test_a_running_stream_holds_exactly_one_slot(monkeypatch):
    monkeypatch.setattr(api, "_SSE_MAX_EVENTS", 2)
    with patch("warden.marketplace.analytics.get_live_metrics", AsyncMock(return_value={})):
        resp = await api.analytics_stream(_Request())
        assert api._sse_open_streams == 0  # not counted until it is iterated
        it = resp.body_iterator.__aiter__()
        await it.__anext__()
        assert api._sse_open_streams == 1
        async for _ in it:
            pass
    assert api._sse_open_streams == 0
