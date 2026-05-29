"""
warden/web3/ipfs_storage.py
IPFS metadata storage for mandate records.
Uses ipfshttpclient when available; falls back to local hash simulation.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os

log = logging.getLogger("warden.blockchain.ipfs")

_IPFS_URL = os.getenv("IPFS_API_URL", "/ip4/127.0.0.1/tcp/5001")


def _pin(data: dict) -> str:
    """Store JSON data on IPFS, return CID. Simulates CID when IPFS unavailable."""
    payload = json.dumps(data, sort_keys=True).encode()
    try:
        import ipfshttpclient  # type: ignore
        client = ipfshttpclient.connect(_IPFS_URL)
        result = client.add_json(data)
        return result
    except Exception:
        # Local simulation: SHA-256 prefixed as Qm... (not a real IPFS CID but deterministic)
        digest = hashlib.sha256(payload).hexdigest()
        return f"Qm{digest[:44]}"


def _fetch(cid: str) -> dict:
    try:
        import ipfshttpclient  # type: ignore
        client = ipfshttpclient.connect(_IPFS_URL)
        return client.get_json(cid)
    except Exception:
        return {"cid": cid, "note": "IPFS unavailable — local simulation"}


class IPFSStorage:
    def store_mandate(self, mandate_data: dict) -> str:
        cid = _pin(mandate_data)
        log.info("Mandate metadata pinned: %s", cid)
        return cid

    def fetch_mandate(self, cid: str) -> dict:
        return _fetch(cid)
