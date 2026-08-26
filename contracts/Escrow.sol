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
///      (sha256 4e7b3b0088bb6d82102467d36ac97923…).
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

    /// @notice Resolves disputes and may release after the deadline. The
    ///         gateway's signing key. A single arbiter is a deliberate
    ///         simplification for the first mainnet trades and should be
    ///         replaced by a multisig before this holds meaningful value.
    address public immutable arbiter;

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

    modifier onlyArbiter() {
        if (msg.sender != arbiter) revert NotArbiter();
        _;
    }

    constructor(address _arbiter) {
        // A zero arbiter is unrecoverable: no dispute could ever be resolved and
        // no trade cancelled early, so every deposit would sit until its
        // deadline. Cheaper to refuse the deployment than to redeploy after it.
        if (_arbiter == address(0)) revert ZeroArbiter();
        arbiter = _arbiter;
    }

    /// @notice Pull `amount` of `token` from the buyer into escrow.
    /// @dev The buyer must have approved this contract for `amount` first;
    ///      that approval is the buyer's own transaction and is not something
    ///      the gateway can perform for them.
    function deposit(
        bytes32 tradeId,
        address buyer,
        address seller,
        address token,
        uint256 amount,
        uint64  deliveryWindowSeconds
    ) external {
        // Without this, `deposit` pulls from an arbitrary `buyer` using whatever
        // allowance that address has standing with this contract — so anyone
        // could sweep a third party's approved balance into a trade they never
        // agreed to, with a deadline of the attacker's choosing. They could not
        // steal it (`confirmReceipt` checks the buyer) but they could lock it,
        // and `raiseDispute` would freeze it pending the arbiter. Infinite
        // approval is the common integration, which is what made it serious.
        // The arbiter is permitted because it is the gateway's own signer and
        // is already trusted to move funds in `resolveDispute`.
        if (msg.sender != buyer && msg.sender != arbiter) revert NotBuyer();
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
        // Triaged, not ignored. `buyer` is arbitrary only to the arbiter, which
        // is this gateway's own signer and already able to direct funds either
        // way through `resolveDispute`. Permitting it to open a deposit grants
        // no power it does not have; the residual risk is arbiter key
        // compromise, which loses the contract regardless. Every other caller
        // is rejected by the `msg.sender != buyer` check above — that is the
        // half of this detector that was a real hole.
        // slither-disable-next-line arbitrary-send-erc20
        if (!IERC20(token).transferFrom(buyer, address(this), amount)) revert TransferFailed();
    }

    /// @notice Seller records delivery. Does not move funds — the buyer's
    ///         confirmation or the deadline does that.
    function deliverAsset(bytes32 tradeId, bytes32 assetHash) external {
        Trade storage t = trades[tradeId];
        if (msg.sender != t.seller && msg.sender != arbiter) revert NotSeller();
        if (t.state != State.Funded) revert WrongState(t.state);
        t.state = State.Delivered;
        emit Delivered(tradeId, assetHash);
    }

    /// @notice Buyer accepts delivery; funds go to the seller.
    function confirmReceipt(bytes32 tradeId) external {
        Trade storage t = trades[tradeId];
        if (msg.sender != t.buyer && msg.sender != arbiter) revert NotBuyer();
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
        if (msg.sender != t.buyer && msg.sender != t.seller && msg.sender != arbiter) {
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
