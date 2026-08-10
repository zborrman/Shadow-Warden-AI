"""
warden/tests/test_clickhouse_selflog_config.py

D-8. Measured on the VPS 2026-08-10: the ClickHouse container held **zero**
GSAM observation rows and 1.74 GiB of active parts, of which 100% was the
server logging about itself (`text_log` 21.5 M rows, `trace_log` 23.5 M,
`asynchronous_metric_log` 730 M, `metric_log` 2.6 M). It was failing background
merges on that data with `Code: 241. Memory limit (total) exceeded`.

`docker/clickhouse/config.d/logging.xml` turns those four off. The mount is the
fragile half: a config file that is not mounted is indistinguishable from one
that is, until the volume has grown two gigabytes again — the same shape as the
liboqs build step that silently did nothing for three minor versions. So assert
the mount, not just the file.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_CONFIG = _REPO / "docker" / "clickhouse" / "config.d" / "logging.xml"

# Every table whose only consumer is ClickHouse itself. Each one is a
# MergeTree that merges, and merging is what ran the container out of memory.
_MUST_BE_OFF = ("text_log", "trace_log", "metric_log", "asynchronous_metric_log")

# Kept, because these are what answer "did the ingest arrive, and what failed"
# once GSAM has a producer — but bounded, so they cannot repeat the incident.
_MUST_BE_BOUNDED = ("query_log", "error_log")


def test_config_disables_the_self_referential_log_tables():
    root = ET.parse(_CONFIG).getroot()
    for name in _MUST_BE_OFF:
        node = root.find(name)
        assert node is not None, f"{name} missing from logging.xml"
        assert node.get("remove") == "1", (
            f"{name} must carry remove=\"1\" — ClickHouse only drops a system log "
            f"table when the element is explicitly removed; an empty element "
            f"leaves the default in place"
        )


def test_the_kept_log_tables_have_a_ttl():
    root = ET.parse(_CONFIG).getroot()
    for name in _MUST_BE_BOUNDED:
        node = root.find(name)
        assert node is not None, f"{name} missing from logging.xml"
        ttl = node.findtext("ttl") or ""
        assert "INTERVAL" in ttl and "DELETE" in ttl, (
            f"{name} is kept, so it needs a TTL; found {ttl!r}"
        )


def test_compose_actually_mounts_the_config():
    """The file only does anything if it reaches /etc/clickhouse-server/config.d."""
    compose = (_REPO / "docker-compose.yml").read_text(encoding="utf-8")
    mount = (
        "./docker/clickhouse/config.d/logging.xml:"
        "/etc/clickhouse-server/config.d/logging.xml:ro"
    )
    assert mount in compose, (
        "docker-compose.yml no longer mounts logging.xml into the ClickHouse "
        "container. Without the mount the server falls back to its defaults and "
        "resumes writing ~2 GB of logs about itself while storing no rows."
    )
