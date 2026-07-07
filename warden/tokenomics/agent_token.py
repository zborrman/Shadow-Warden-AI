"""
warden/tokenomics/agent_token.py
──────────────────────────────────
Warden Agent Token (WAT) — ERC-20 on Polygon Amoy.

In production, WAT_TOKEN_ADDRESS must point to a deployed ERC-20 contract.
In simulation mode (WAT_SIMULATE=true or web3 unavailable), all operations
are tracked in Redis with no on-chain transactions.

ERC-20 ABI subset (mint, transfer, balanceOf) is embedded below.
"""
from __future__ import annotations

import logging
from typing import Any

from warden.config import settings

log = logging.getLogger("warden.tokenomics.agent_token")

_WAT_ADDRESS  = settings.wat_token_address
_RPC_URL      = settings.polygon_amoy_rpc_url
_ADMIN_WALLET = settings.wat_admin_wallet
_ADMIN_KEY_HEX= settings.wat_admin_private_key
_SIMULATE     = settings.wat_simulate
_REDIS_URL    = settings.redis_url

# Minimal ABI for mint / transfer / balanceOf
_ERC20_ABI = [
    {"type":"function","name":"balanceOf","inputs":[{"name":"account","type":"address"}],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
    {"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"},
    {"type":"function","name":"mint","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},
]

_WAT_DECIMALS = 18
_WAT_UNIT     = 10 ** _WAT_DECIMALS


def _redis():
    try:
        import redis as _r  # noqa: PLC0415
        if _REDIS_URL.startswith("memory://"):
            return None
        return _r.from_url(_REDIS_URL, decode_responses=True)
    except Exception:
        return None


def _sim_key(agent_id: str) -> str:
    return f"wat:balance:{agent_id}"


_SIMULATION_BALANCES: dict[str, float] = {}  # fallback when Redis unavailable


class AgentToken:
    """
    WAT ERC-20 interface.

    When WAT_SIMULATE=true or web3/contract unavailable, all operations
    use Redis as a ledger (no real blockchain transaction).
    """

    def __init__(self) -> None:
        self._contract: Any = None
        self._w3: Any       = None
        if not _SIMULATE and _RPC_URL and _WAT_ADDRESS:
            self._init_web3()

    def _init_web3(self) -> None:
        try:
            from web3 import Web3  # noqa: PLC0415
            w3 = Web3(Web3.HTTPProvider(_RPC_URL, request_kwargs={"timeout": 10}))
            if not w3.is_connected():
                log.warning("AgentToken: Web3 not connected to %s — simulation mode.", _RPC_URL)
                return
            self._w3       = w3
            self._contract = w3.eth.contract(
                address=Web3.to_checksum_address(_WAT_ADDRESS),
                abi=_ERC20_ABI,
            )
            log.info("AgentToken: connected to WAT contract %s on %s", _WAT_ADDRESS, _RPC_URL)
        except Exception as exc:
            log.warning("AgentToken: Web3 init failed (%s) — simulation mode.", exc)

    @property
    def _simulating(self) -> bool:
        return _SIMULATE or self._contract is None

    def mint(self, agent_id: str, amount: float) -> dict:
        """Admin — mint *amount* WAT to *agent_id*. Returns tx metadata."""
        if self._simulating:
            return self._sim_mint(agent_id, amount)
        try:
            from web3 import Web3  # noqa: PLC0415
            addr   = Web3.to_checksum_address(agent_id)
            units  = int(amount * _WAT_UNIT)
            nonce  = self._w3.eth.get_transaction_count(Web3.to_checksum_address(_ADMIN_WALLET))
            tx     = self._contract.functions.mint(addr, units).build_transaction({
                "from":     Web3.to_checksum_address(_ADMIN_WALLET),
                "nonce":    nonce,
                "gas":      100_000,
                "gasPrice": self._w3.eth.gas_price,
            })
            signed = self._w3.eth.account.sign_transaction(tx, private_key=_ADMIN_KEY_HEX)
            tx_hash = self._w3.eth.send_raw_transaction(signed.rawTransaction)
            return {"simulated": False, "tx_hash": tx_hash.hex(), "amount": amount, "agent_id": agent_id}
        except Exception as exc:
            log.warning("AgentToken.mint on-chain error: %s — falling back to simulation.", exc)
            return self._sim_mint(agent_id, amount)

    def transfer(self, from_agent: str, to_agent: str, amount: float) -> dict:
        """Transfer *amount* WAT from *from_agent* to *to_agent*."""
        if self._simulating:
            return self._sim_transfer(from_agent, to_agent, amount)
        try:
            from web3 import Web3  # noqa: PLC0415
            to_addr = Web3.to_checksum_address(to_agent)
            units   = int(amount * _WAT_UNIT)
            nonce   = self._w3.eth.get_transaction_count(Web3.to_checksum_address(from_agent))
            tx      = self._contract.functions.transfer(to_addr, units).build_transaction({
                "from":     Web3.to_checksum_address(from_agent),
                "nonce":    nonce,
                "gas":      80_000,
                "gasPrice": self._w3.eth.gas_price,
            })
            signed  = self._w3.eth.account.sign_transaction(tx, private_key=_ADMIN_KEY_HEX)
            tx_hash = self._w3.eth.send_raw_transaction(signed.rawTransaction)
            return {"simulated": False, "tx_hash": tx_hash.hex(), "amount": amount}
        except Exception as exc:
            log.warning("AgentToken.transfer on-chain error: %s — simulation.", exc)
            return self._sim_transfer(from_agent, to_agent, amount)

    def balance_of(self, agent_id: str) -> float:
        """Return WAT balance for *agent_id*."""
        if self._simulating:
            return self._sim_balance(agent_id)
        try:
            from web3 import Web3  # noqa: PLC0415
            raw = self._contract.functions.balanceOf(Web3.to_checksum_address(agent_id)).call()
            return raw / _WAT_UNIT
        except Exception as exc:
            log.warning("AgentToken.balance_of on-chain error: %s — simulation.", exc)
            return self._sim_balance(agent_id)

    # ── Simulation helpers ────────────────────────────────────────────────────

    def _sim_balance(self, agent_id: str) -> float:
        r = _redis()
        if r:
            try:
                raw = r.get(_sim_key(agent_id))
                if raw is not None:
                    return float(raw)
            except Exception:
                pass
        return _SIMULATION_BALANCES.get(agent_id, 0.0)

    def _sim_mint(self, agent_id: str, amount: float) -> dict:
        r = _redis()
        if r:
            try:
                r.incrbyfloat(_sim_key(agent_id), amount)
                r.expire(_sim_key(agent_id), 86_400 * 365)
            except Exception:
                r = None
        if not r:
            _SIMULATION_BALANCES[agent_id] = _SIMULATION_BALANCES.get(agent_id, 0.0) + amount
        return {"simulated": True, "amount": amount, "agent_id": agent_id, "new_balance": self._sim_balance(agent_id)}

    def _sim_transfer(self, from_agent: str, to_agent: str, amount: float) -> dict:
        from_bal = self._sim_balance(from_agent)
        if from_bal < amount:
            raise ValueError(f"Insufficient WAT: {from_bal:.4f} < {amount:.4f}")
        r = _redis()
        if r:
            try:
                pipe = r.pipeline()
                pipe.incrbyfloat(_sim_key(from_agent), -amount)
                pipe.incrbyfloat(_sim_key(to_agent),    amount)
                pipe.expire(_sim_key(from_agent), 86_400 * 365)
                pipe.expire(_sim_key(to_agent),   86_400 * 365)
                pipe.execute()
            except Exception:
                r = None
        if not r:
            _SIMULATION_BALANCES[from_agent] = _SIMULATION_BALANCES.get(from_agent, 0.0) - amount
            _SIMULATION_BALANCES[to_agent]   = _SIMULATION_BALANCES.get(to_agent,   0.0) + amount
        return {"simulated": True, "from": from_agent, "to": to_agent, "amount": amount}


# ── Singleton ─────────────────────────────────────────────────────────────────

_token: AgentToken | None = None


def get_agent_token() -> AgentToken:
    global _token
    if _token is None:
        _token = AgentToken()
    return _token
