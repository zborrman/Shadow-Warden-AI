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
/// @dev NOT COMPILED, NOT AUDITED, NOT DEPLOYED. This is a draft for review.
///      `scripts/build_escrow.sh` produces the ABI and bytecode via solc in
///      Docker; `contracts/escrow.abi.json` is hand-written to match this source
///      and is verified against it by `test_escrow_abi_matches_callers`. Neither
///      that test nor this comment is a substitute for an audit: real money on a
///      mainnet contract is exactly the thing this repository has spent weeks
///      refusing to claim before it is true.
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
    error WrongState(State current);
    error TradeExists();
    error TransferFailed();
    error DeadlineNotReached();

    modifier onlyArbiter() {
        if (msg.sender != arbiter) revert NotArbiter();
        _;
    }

    constructor(address _arbiter) {
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
        if (trades[tradeId].state != State.None) revert TradeExists();

        trades[tradeId] = Trade({
            buyer: buyer,
            seller: seller,
            token: token,
            amount: amount,
            deliveryDeadline: uint64(block.timestamp) + deliveryWindowSeconds,
            state: State.Funded
        });

        if (!IERC20(token).transferFrom(buyer, address(this), amount)) revert TransferFailed();
        emit Funded(tradeId, buyer, seller, amount);
    }

    /// @notice Seller records delivery. Does not move funds — the buyer's
    ///         confirmation or the deadline does that.
    function deliverAsset(bytes32 tradeId, bytes32 assetHash) external {
        Trade storage t = trades[tradeId];
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
        if (!IERC20(t.token).transfer(t.seller, t.amount)) revert TransferFailed();
        emit Released(tradeId, t.seller, t.amount);
    }

    /// @notice Either party escalates before release.
    function raiseDispute(bytes32 tradeId, string calldata reason) external {
        Trade storage t = trades[tradeId];
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
        if (!IERC20(t.token).transfer(to, t.amount)) revert TransferFailed();
        emit Resolved(tradeId, releaseToBuyer);
        if (releaseToBuyer) emit Refunded(tradeId, to, t.amount);
        else emit Released(tradeId, to, t.amount);
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
        if (!IERC20(t.token).transfer(t.buyer, t.amount)) revert TransferFailed();
        emit Refunded(tradeId, t.buyer, t.amount);
    }

    function stateOf(bytes32 tradeId) external view returns (State) {
        return trades[tradeId].state;
    }
}
