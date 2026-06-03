// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ISignatureTransfer
 * @notice Interface for Permit2's SignatureTransfer functionality
 * @dev Based on Uniswap's canonical Permit2 contract. Vendored from x402.
 */
interface ISignatureTransfer {
    /// @notice The token and amount details for a transfer signed in the permit transfer signature
    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    /// @notice The signed permit message for a single token transfer
    struct PermitTransferFrom {
        TokenPermissions permitted;
        uint256 nonce;
        uint256 deadline;
    }

    /// @notice Specifies the recipient address and amount for batched transfers.
    struct SignatureTransferDetails {
        address to;
        uint256 requestedAmount;
    }

    function nonceBitmap(address, uint256) external view returns (uint256);

    function permitTransferFrom(
        PermitTransferFrom memory permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes calldata signature
    ) external;

    function permitWitnessTransferFrom(
        PermitTransferFrom memory permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 witness,
        string calldata witnessTypeString,
        bytes calldata signature
    ) external;
}
