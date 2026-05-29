// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Shadow Warden AI — On-chain Spending Mandate
 * Deployed on Sepolia/Polygon for AP2 decentralized payments.
 */
contract Mandate {
    struct MandateRecord {
        string  tenantId;
        uint256 maxAmount;      // in USD cents
        uint256 spentAmount;
        uint256 validUntil;     // unix timestamp
        address owner;
        bool    active;
        string  ipfsHash;       // metadata CID
    }

    mapping(bytes32 => MandateRecord) public mandates;
    mapping(bytes32 => string[])      public allowedMerchants;

    event MandateCreated(bytes32 indexed mandateId, string tenantId, uint256 maxAmount);
    event PaymentExecuted(bytes32 indexed mandateId, uint256 amount, string merchant);
    event MandateRevoked(bytes32 indexed mandateId);

    function createMandate(
        bytes32 mandateId,
        string  calldata tenantId,
        uint256 maxAmount,
        uint256 validUntil,
        string[] calldata merchants,
        string  calldata ipfsHash
    ) external {
        require(mandates[mandateId].owner == address(0), "Mandate exists");
        require(maxAmount > 0, "Amount must be positive");
        require(validUntil > block.timestamp, "Invalid expiry");

        mandates[mandateId] = MandateRecord({
            tenantId:    tenantId,
            maxAmount:   maxAmount,
            spentAmount: 0,
            validUntil:  validUntil,
            owner:       msg.sender,
            active:      true,
            ipfsHash:    ipfsHash
        });
        for (uint i = 0; i < merchants.length; i++) {
            allowedMerchants[mandateId].push(merchants[i]);
        }
        emit MandateCreated(mandateId, tenantId, maxAmount);
    }

    function executePayment(
        bytes32 mandateId,
        uint256 amount,
        string  calldata merchant
    ) external {
        MandateRecord storage m = mandates[mandateId];
        require(m.active, "Mandate not active");
        require(block.timestamp <= m.validUntil, "Mandate expired");
        require(m.spentAmount + amount <= m.maxAmount, "Exceeds limit");

        m.spentAmount += amount;
        if (m.spentAmount >= m.maxAmount) m.active = false;
        emit PaymentExecuted(mandateId, amount, merchant);
    }

    function revokeMandate(bytes32 mandateId) external {
        require(mandates[mandateId].owner == msg.sender, "Not owner");
        mandates[mandateId].active = false;
        emit MandateRevoked(mandateId);
    }

    function getMandate(bytes32 mandateId)
        external view returns (MandateRecord memory, string[] memory)
    {
        return (mandates[mandateId], allowedMerchants[mandateId]);
    }
}
