// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @title Shadow Warden marketplace escrow (singleton, ERC-20)
/// @notice One deployed instance per chain holds every trade's state, keyed by
///         `tradeId`. The gateway addresses it through
///         `ESCROW_CONTRACT_<CHAIN>` and calls the six functions below —
///         `deposit`, `deliverAsset`, `confirmReceipt`, `raiseDispute`,
///         `resolveDispute`, `cancelDeposit` — which are the names
///         `warden/marketplace/escrow.py` already sends. The interface was taken
///         from the caller rather than invented, so nothing has to be renamed on
///         either side to make them meet.
///
/// @dev COMPILED, NOT AUDITED, NOT DEPLOYED.
///      solc 0.8.24, --optimize --optimize-runs 200, via `scripts/build_escrow.sh`.
///      Artefacts: `contracts/escrow.abi.json`, `contracts/escrow.bin`
///      (sha256 recorded in the PR that built them, not here: comments are
///      part of the metadata hash, so a hash quoted in the source changes it).
///      Rebuild and diff before trusting either. Compilation proves the source is
///      well-formed and nothing else — not that the logic is right, not that the
///      funds are safe. An audit is a separate thing this has not had, and real
///      money on a mainnet contract is exactly what this repository has spent
///      weeks refusing to claim before it is true.
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Escrow {
    enum State { None, Funded, Delivered, Released, Refunded, Disputed }

    struct Trade {
        address buyer;
        address seller;
        address token;      // USDC on the target chain
        uint256 amount;
        uint64  deliveryDeadline;
        State   state;
    }

    /// @notice Resolves disputes. Decides who receives disputed funds, and
    ///         nothing else. Intended to be a multisig held off the gateway
    ///         host: it is consulted rarely and by a human, so it does not need
    ///         to be reachable by software.
    address public immutable arbiter;

    /// @notice Relays routine calls on behalf of a party. The gateway's hot
    ///         signing key.
    ///
    ///         These were one address until 2026-09-03, and that made the
    ///         multisig impossible rather than merely absent: `deposit`,
    ///         `deliverAsset` and `confirmReceipt` accept the arbiter so the
    ///         gateway can act for a counterparty, and those run on every trade,
    ///         unattended. (`deposit` no longer accepts either role on its own:
    ///         since 2026-11-01 it needs the buyer's signed consent.) Putting a 2-of-3 multisig in `arbiter` would have
    ///         required two humans to sign each deposit.
    ///
    ///         Split so the key that must be hot is the one that cannot decide
    ///         a dispute, and the key that decides disputes never has to be hot.
    ///         The operator can move a trade along its agreed path; it cannot
    ///         choose who wins.
    address public immutable operator;

    mapping(bytes32 => Trade) public trades;

    event Funded(bytes32 indexed tradeId, address buyer, address seller, uint256 amount);
    event Delivered(bytes32 indexed tradeId, bytes32 assetHash);
    event Released(bytes32 indexed tradeId, address to, uint256 amount);
    event Refunded(bytes32 indexed tradeId, address to, uint256 amount);
    event Disputed(bytes32 indexed tradeId, string reason);
    event Resolved(bytes32 indexed tradeId, bool releaseToBuyer);

    error NotArbiter();
    error NotBuyer();
    error NotSeller();
    error NotParty();
    error ZeroArbiter();
    error WrongState(State current);
    error TradeExists();
    error TransferFailed();
    error DeadlineNotReached();
    error ZeroOperator();
    error BadSignature();
    error IntentExpired();

    modifier onlyArbiter() {
        if (msg.sender != arbiter) revert NotArbiter();
        _;
    }

    constructor(address _arbiter, address _operator) {
        // A zero arbiter is unrecoverable: no dispute could ever be resolved and
        // no trade cancelled early, so every deposit would sit until its
        // deadline. Cheaper to refuse the deployment than to redeploy after it.
        if (_arbiter == address(0)) revert ZeroArbiter();
        // A zero operator is merely useless rather than unrecoverable — the
        // parties could still call for themselves — but it silently disables
        // every gateway-relayed trade, so it is refused at the same gate.
        if (_operator == address(0)) revert ZeroOperator();
        arbiter  = _arbiter;
        operator = _operator;
    }

    /// @notice EIP-712 type of the buyer's consent to one deposit. The buyer is
    ///         the signer, so it is not a field: a signature recovers to exactly
    ///         one address, and that address is the only one whose allowance the
    ///         deposit may draw on.
    bytes32 public constant DEPOSIT_INTENT_TYPEHASH = keccak256(
        "DepositIntent(bytes32 tradeId,address seller,address token,uint256 amount,"
        "uint64 deliveryWindowSeconds,uint256 deadline)"
    );

    // secp256k1n / 2. A signature with a higher `s` is the malleable twin of a
    // valid one; refusing it keeps one consent to one signature.
    uint256 private constant _HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @notice EIP-712 domain separator, recomputed per call so a chain fork
    ///         cannot replay a signature made for the other branch.
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("ShadowWardenEscrow")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    /// @notice The digest a buyer signs to consent to `deposit`.
    function depositIntentDigest(
        bytes32 tradeId,
        address seller,
        address token,
        uint256 amount,
        uint64  deliveryWindowSeconds,
        uint256 deadline
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            DEPOSIT_INTENT_TYPEHASH, tradeId, seller, token, amount,
            deliveryWindowSeconds, deadline
        ));
        return keccak256(abi.encodePacked(hex"1901", domainSeparator(), structHash));
    }

    /// @notice Pull `amount` of `token` from the buyer into escrow.
    /// @dev The buyer must have approved this contract for `amount` first;
    ///      that approval is the buyer's own transaction and is not something
    ///      the gateway can perform for them.
    ///
    ///      Either the buyer sends this itself (`buyerSignature` empty), or the
    ///      buyer has signed a `DepositIntent` for exactly these arguments and
    ///      anyone may relay it. Until 2026-11-01 the operator and the arbiter
    ///      could call it for any buyer with no consent at all — and since the
    ///      operator can also call `deliverAsset` and `confirmReceipt`, a stolen
    ///      hot key could open a trade from any approved buyer to a seller of its
    ///      own choosing and pay it out in three transactions. The allowance was
    ///      the buyer's only protection, and infinite approval is the common
    ///      integration. A relayer's identity grants nothing now; the signature
    ///      is the authority, and the trade id makes it single-use.
    function deposit(
        bytes32 tradeId,
        address buyer,
        address seller,
        address token,
        uint256 amount,
        uint64  deliveryWindowSeconds,
        uint256 intentDeadline,
        bytes calldata buyerSignature
    ) external {
        if (msg.sender != buyer) {
            // Signature first, so a deposit with no consent at all says so,
            // rather than reporting the expiry of a deadline nobody signed.
            bytes32 digest = depositIntentDigest(
                tradeId, seller, token, amount, deliveryWindowSeconds, intentDeadline
            );
            if (buyer == address(0) || _recover(digest, buyerSignature) != buyer) {
                revert BadSignature();
            }
            if (block.timestamp > intentDeadline) revert IntentExpired();
        }
        if (trades[tradeId].state != State.None) revert TradeExists();

        trades[tradeId] = Trade({
            buyer: buyer,
            seller: seller,
            token: token,
            amount: amount,
            deliveryDeadline: uint64(block.timestamp) + deliveryWindowSeconds,
            state: State.Funded
        });

        emit Funded(tradeId, buyer, seller, amount);
        // `buyer` is either `msg.sender` or the address the buyer's own EIP-712
        // signature over these exact arguments recovers to (checked above), so
        // the transfer only ever draws on an allowance whose owner consented to
        // this trade, this seller, this token and this amount.
        // slither-disable-next-line arbitrary-send-erc20
        if (!IERC20(token).transferFrom(buyer, address(this), amount)) revert TransferFailed();
    }

    /// @dev Plain ecrecover over a 65-byte (r, s, v) signature, refusing the
    ///      malleable high-`s` form. Returns address(0) on any malformed input,
    ///      which never equals a non-zero buyer.
    function _recover(bytes32 digest, bytes calldata sig) private pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        if (uint256(s) > _HALF_N) return address(0);
        return ecrecover(digest, v, r, s);
    }

    /// @notice Seller records delivery. Does not move funds — the buyer's
    ///         confirmation or the deadline does that.
    function deliverAsset(bytes32 tradeId, bytes32 assetHash) external {
        Trade storage t = trades[tradeId];
        if (msg.sender != t.seller && msg.sender != operator && msg.sender != arbiter)
            revert NotSeller();
        if (t.state != State.Funded) revert WrongState(t.state);
        t.state = State.Delivered;
        emit Delivered(tradeId, assetHash);
    }

    /// @notice Buyer accepts delivery; funds go to the seller.
    function confirmReceipt(bytes32 tradeId) external {
        Trade storage t = trades[tradeId];
        if (msg.sender != t.buyer && msg.sender != operator && msg.sender != arbiter)
            revert NotBuyer();
        if (t.state != State.Delivered) revert WrongState(t.state);
        t.state = State.Released;
        emit Released(tradeId, t.seller, t.amount);
        if (!IERC20(t.token).transfer(t.seller, t.amount)) revert TransferFailed();
    }

    /// @notice Either party escalates before release.
    function raiseDispute(bytes32 tradeId, string calldata reason) external {
        Trade storage t = trades[tradeId];
        // The comment said "either party"; the code accepted anyone, so a
        // stranger could freeze a funded trade until the arbiter intervened.
        if (
            msg.sender != t.buyer && msg.sender != t.seller
            && msg.sender != operator && msg.sender != arbiter
        ) {
            revert NotParty();
        }
        if (t.state != State.Funded && t.state != State.Delivered) revert WrongState(t.state);
        t.state = State.Disputed;
        emit Disputed(tradeId, reason);
    }

    /// @notice Arbiter decides a disputed trade.
    function resolveDispute(bytes32 tradeId, bool releaseToBuyer) external onlyArbiter {
        Trade storage t = trades[tradeId];
        if (t.state != State.Disputed) revert WrongState(t.state);
        address to = releaseToBuyer ? t.buyer : t.seller;
        t.state = releaseToBuyer ? State.Refunded : State.Released;
        emit Resolved(tradeId, releaseToBuyer);
        if (releaseToBuyer) emit Refunded(tradeId, to, t.amount);
        else emit Released(tradeId, to, t.amount);
        if (!IERC20(t.token).transfer(to, t.amount)) revert TransferFailed();
    }

    /// @notice Refund the buyer when the seller never delivered in time.
    /// @dev Callable by anyone once the deadline passes: a refund that depends
    ///      on the counterparty's cooperation is not a refund.
    function cancelDeposit(bytes32 tradeId) external {
        Trade storage t = trades[tradeId];
        if (t.state != State.Funded) revert WrongState(t.state);
        // Arbiter, not operator: an early cancel refunds the buyer, which is a
        // decision about who gets the money rather than a step along the agreed
        // path. The hot key must not be able to take it.
        if (block.timestamp < t.deliveryDeadline && msg.sender != arbiter) {
            revert DeadlineNotReached();
        }
        t.state = State.Refunded;
        emit Refunded(tradeId, t.buyer, t.amount);
        if (!IERC20(t.token).transfer(t.buyer, t.amount)) revert TransferFailed();
    }

    function stateOf(bytes32 tradeId) external view returns (State) {
        return trades[tradeId].state;
    }
}
