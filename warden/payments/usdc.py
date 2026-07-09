"""
warden/payments/usdc.py
─────────────────────────
USDC stablecoin payment rail.

In production: Coinbase Commerce API or direct on-chain USDC transfer
  verification (Polygon Amoy, Arbitrum Sepolia, Ethereum Mainnet).

In simulation mode (USDC_SIMULATE=true or no API key):
  Payment intents are stored in Redis with configurable auto-confirm TTL.

Integration with AP2:
  If the AP2 mandate specifies payment_rail="usdc", call
  USDCService.create_payment_intent() and return the intent_id to the buyer.
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from warden.config import settings

log = logging.getLogger("warden.payments.usdc")

_SIMULATE    = settings.usdc_simulate
_CB_API_KEY  = settings.coinbase_commerce_api_key
_REDIS_URL   = settings.redis_url
_INTENT_TTL  = settings.usdc_intent_ttl_s  # 24 h default


@dataclass
class PaymentIntent:
    intent_id:       str
    amount_usd:      float
    merchant_wallet: str
    status:          str    # pending | confirmed | failed | expired
    payment_rail:    str    # usdc
    chain:           str
    created_at:      str
    confirmed_at:    str | None = None
    tx_hash:         str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _redis():
    try:
        import redis as _r  # noqa: PLC0415
        if _REDIS_URL.startswith("memory://"):
            return None
        return _r.from_url(_REDIS_URL, decode_responses=True)
    except Exception:
        return None


def _intent_key(intent_id: str) -> str:
    return f"usdc:intent:{intent_id}"


_MEMORY_INTENTS: dict[str, dict] = {}  # fallback when Redis unavailable


class USDCService:
    """USDC payment intent lifecycle."""

    def __init__(self, chain: str = "polygon_amoy") -> None:
        self.chain = chain

    # ── Create intent ─────────────────────────────────────────────────────────

    def create_payment_intent(self, amount_usd: float, merchant_wallet: str) -> PaymentIntent:
        """
        Create a USDC payment intent.

        Returns a PaymentIntent with a unique intent_id.
        The buyer must send exactly *amount_usd* USDC to *merchant_wallet*.
        """
        intent_id = f"USDC-{uuid.uuid4().hex[:12].upper()}"
        intent    = PaymentIntent(
            intent_id=intent_id,
            amount_usd=amount_usd,
            merchant_wallet=merchant_wallet,
            status="pending",
            payment_rail="usdc",
            chain=self.chain,
            created_at=datetime.now(UTC).isoformat(),
        )
        self._persist(intent)

        if not _SIMULATE and _CB_API_KEY:
            self._create_coinbase_charge(intent)

        log.info("USDCService: intent created %s amount=%.2f chain=%s", intent_id, amount_usd, self.chain)
        return intent

    # ── Verify / poll ─────────────────────────────────────────────────────────

    def verify_payment(self, intent_id: str) -> PaymentIntent | None:
        """
        Check the status of a payment intent.

        In production: poll blockchain for USDC transfer to merchant_wallet.
        In simulation: auto-confirm after first verify call.
        """
        intent = self._load(intent_id)
        if intent is None:
            return None

        if intent.status == "confirmed":
            return intent

        if _SIMULATE:
            # Simulation: auto-confirm on first verification call
            intent.status       = "confirmed"
            intent.confirmed_at = datetime.now(UTC).isoformat()
            intent.tx_hash      = f"sim_tx_{uuid.uuid4().hex[:16]}"
            self._persist(intent)
            log.info("USDCService [sim]: auto-confirmed intent %s", intent_id)
            return intent

        # Real: check Coinbase Commerce or on-chain
        return self._check_onchain(intent)

    def get_intent(self, intent_id: str) -> PaymentIntent | None:
        return self._load(intent_id)

    # ── Persistence ───────────────────────────────────────────────────────────

    def _persist(self, intent: PaymentIntent) -> None:
        _MEMORY_INTENTS[intent.intent_id] = intent.to_dict()
        r = _redis()
        if r:
            try:
                r.set(_intent_key(intent.intent_id), json.dumps(intent.to_dict()), ex=_INTENT_TTL)
            except Exception as exc:
                log.debug("USDCService._persist Redis error: %s", exc)

    def _load(self, intent_id: str) -> PaymentIntent | None:
        r = _redis()
        if r:
            try:
                raw = r.get(_intent_key(intent_id))
                if raw:
                    d = json.loads(raw)
                    return PaymentIntent(**d)
            except Exception as exc:
                log.debug("USDCService._load Redis error: %s", exc)
        d = _MEMORY_INTENTS.get(intent_id)
        if d:
            return PaymentIntent(**d)
        return None

    # ── Coinbase Commerce ─────────────────────────────────────────────────────

    def _create_coinbase_charge(self, intent: PaymentIntent) -> None:
        try:
            import httpx  # noqa: PLC0415
            resp = httpx.post(
                "https://api.commerce.coinbase.com/charges",
                headers={
                    "X-CC-Api-Key":   _CB_API_KEY,
                    "X-CC-Version":   "2018-03-22",
                    "Content-Type":   "application/json",
                },
                json={
                    "name":         "Shadow Warden WAT Purchase",
                    "description":  f"Marketplace payment {intent.intent_id}",
                    "pricing_type": "fixed_price",
                    "local_price":  {"amount": str(intent.amount_usd), "currency": "USD"},
                    "metadata":     {"intent_id": intent.intent_id},
                },
                timeout=10.0,
            )
            if resp.status_code == 201:
                charge_id = resp.json()["data"]["id"]
                log.info("USDCService: Coinbase Commerce charge created %s", charge_id)
        except Exception as exc:
            log.warning("USDCService._create_coinbase_charge: %s", exc)

    def _check_onchain(self, intent: PaymentIntent) -> PaymentIntent:
        # Placeholder: in production, call Alchemy/Infura to scan recent USDC transfers
        log.debug("USDCService._check_onchain: not implemented (real blockchain polling required).")
        return intent


# ── Singleton ─────────────────────────────────────────────────────────────────

_svc_by_chain: dict[str, USDCService] = {}


def get_usdc_service(chain: str = "polygon_amoy") -> USDCService:
    if chain not in _svc_by_chain:
        _svc_by_chain[chain] = USDCService(chain=chain)
    return _svc_by_chain[chain]
