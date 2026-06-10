// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Escrow
 * @notice Single-trade escrow for the Shadow Warden M2M Agentic Marketplace.
 *
 * Lifecycle
 * ---------
 *   deposit()        -> status: Funded
 *   deliverAsset()   -> status: Delivered
 *   confirmReceipt() -> status: Confirmed  (funds released to seller)
 *   raiseDispute()   -> status: Disputed
 *   resolveDispute() -> status: ResolvedBuyer | ResolvedSeller
 *   cancelDeposit()  -> status: Cancelled   (buyer refund after timeout)
 */
contract Escrow {
    enum Status {
        PendingDeposit,
        Funded,
        Delivered,
        Confirmed,
        Disputed,
        ResolvedBuyer,
        ResolvedSeller,
        Cancelled
    }

    address public immutable buyer;
    address public immutable seller;
    address public immutable arbitrator;
    uint256 public immutable depositDeadline;  // buyer must fund before this
    uint256 public immutable deliveryDeadline; // seller must deliver within 48h of funding

    Status  public status;
    bytes32 public assetHash;

    event Funded(address indexed buyer, uint256 amount);
    event AssetDelivered(bytes32 indexed assetHash);
    event ReceiptConfirmed(address indexed buyer);
    event DisputeRaised(address indexed by, string reason);
    event DisputeResolved(bool releasedToBuyer);
    event Cancelled(address indexed by);

    modifier onlyBuyer()     { require(msg.sender == buyer,      "Not buyer");     _; }
    modifier onlySeller()    { require(msg.sender == seller,     "Not seller");    _; }
    modifier onlyArbitrator(){ require(msg.sender == arbitrator, "Not arbitrator"); _; }

    constructor(
        address _buyer,
        address _seller,
        address _arbitrator,
        uint256 _depositWindowHours,
        uint256 _deliveryWindowHours
    ) {
        buyer         = _buyer;
        seller        = _seller;
        arbitrator    = _arbitrator;
        depositDeadline  = block.timestamp + _depositWindowHours  * 1 hours;
        deliveryDeadline = block.timestamp + _deliveryWindowHours * 1 hours;
        status        = Status.PendingDeposit;
    }

    // ── Buyer: deposit funds ──────────────────────────────────────────────────

    function deposit() external payable onlyBuyer {
        require(status == Status.PendingDeposit, "Wrong status");
        require(msg.value > 0,                   "No value sent");
        require(block.timestamp <= depositDeadline, "Deposit deadline passed");
        status = Status.Funded;
        emit Funded(msg.sender, msg.value);
    }

    // ── Seller: deliver asset hash ────────────────────────────────────────────

    function deliverAsset(bytes32 _assetHash) external onlySeller {
        require(status == Status.Funded, "Not funded");
        assetHash = _assetHash;
        status    = Status.Delivered;
        emit AssetDelivered(_assetHash);
    }

    // ── Buyer: confirm receipt → release funds to seller ─────────────────────

    function confirmReceipt() external onlyBuyer {
        require(status == Status.Delivered, "Asset not delivered");
        status = Status.Confirmed;
        (bool sent, ) = seller.call{value: address(this).balance}("");
        require(sent, "Transfer to seller failed");
        emit ReceiptConfirmed(msg.sender);
    }

    // ── Either party: raise dispute ───────────────────────────────────────────

    function raiseDispute(string calldata reason) external {
        require(msg.sender == buyer || msg.sender == seller, "Not a party");
        require(
            status == Status.Funded || status == Status.Delivered,
            "Cannot dispute in current status"
        );
        status = Status.Disputed;
        emit DisputeRaised(msg.sender, reason);
    }

    // ── Arbitrator: resolve dispute ───────────────────────────────────────────

    function resolveDispute(bool releaseToBuyer) external onlyArbitrator {
        require(status == Status.Disputed, "No active dispute");
        address recipient;
        if (releaseToBuyer) {
            status    = Status.ResolvedBuyer;
            recipient = buyer;
        } else {
            status    = Status.ResolvedSeller;
            recipient = seller;
        }
        (bool sent, ) = recipient.call{value: address(this).balance}("");
        require(sent, "Transfer failed");
        emit DisputeResolved(releaseToBuyer);
    }

    // ── Buyer: cancel after delivery deadline (refund) ───────────────────────

    function cancelDeposit() external onlyBuyer {
        require(
            status == Status.Funded || status == Status.PendingDeposit,
            "Cannot cancel"
        );
        require(block.timestamp > deliveryDeadline, "Delivery window still open");
        status = Status.Cancelled;
        (bool sent, ) = buyer.call{value: address(this).balance}("");
        require(sent, "Refund failed");
        emit Cancelled(msg.sender);
    }

    // ── View helpers ──────────────────────────────────────────────────────────

    function balance() external view returns (uint256) {
        return address(this).balance;
    }
}
