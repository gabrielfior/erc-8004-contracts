// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {ISignatureTransfer} from "./interfaces/ISignatureTransfer.sol";
import {IIdentityRegistry} from "./interfaces/IIdentityRegistry.sol";
import {ITicketMinter} from "./interfaces/ITicketMinter.sol";

/// @notice Minimal EIP-3009 view used by TicketMinter. USDC and similar tokens implement the
///         bytes-overload of `transferWithAuthorization`.
interface IERC3009 {
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external;
}

/// @title TicketMinter
/// @notice Mints an on-chain x402 job ticket atomically with token settlement.
/// @dev PERMISSIONLESS minting. Both settlement paths are self-authorizing — the
///      payer's own signature authorizes the exact transfer (amount + destination),
///      so no facilitator allowlist is required:
///        1. EIP-3009 `transferWithAuthorization` — payer-signed, the token verifies it.
///        2. Permit2 `permitWitnessTransferFrom` — payer-signed, the witness binds ticket
///           metadata and destination.
///      The approval-based `transferFrom` path was intentionally removed: it would let an
///      arbitrary caller drain a payer's standing approval, which is exactly what an
///      allowlist would otherwise have to guard against.
/// @dev NON-UPGRADEABLE. Deploy per chain with `reputationRegistry_` set to the (already-deployed)
///      ReputationRegistry proxy address; that binding is immutable and survives registry upgrades.
contract TicketMinter is ITicketMinter, EIP712 {
    using ECDSA for bytes32;

    /// @notice EIP-712 typehash for the payer's ticket-metadata authorization on the EIP-3009 path.
    ///         Binds the ticket metadata to the exact payment (token/payTo/value/nonce), so a relayer
    ///         cannot re-attribute a payer's EIP-3009 payment to a different agent/interaction.
    bytes32 public constant TICKET_MINT_AUTHORIZATION_TYPEHASH = keccak256(
        "TicketMintAuthorization(uint256 agentId,bytes32 requestHash,bytes32 interactionHash,string endpoint,address token,address payTo,uint256 value,bytes32 nonce)"
    );

    /// @notice EIP-712 type string for the Permit2 witness binding the ticket.
    string public constant TICKET_WITNESS_TYPE_STRING =
        "TicketWitness witness)TicketWitness(address payer,uint256 agentId,bytes32 requestHash,bytes32 interactionHash,string endpoint,address payTo,uint256 validAfter)TokenPermissions(address token,uint256 amount)";

    /// @notice EIP-712 typehash for the Permit2 ticket witness struct.
    bytes32 public constant TICKET_WITNESS_TYPEHASH = keccak256(
        "TicketWitness(address payer,uint256 agentId,bytes32 requestHash,bytes32 interactionHash,string endpoint,address payTo,uint256 validAfter)"
    );

    ISignatureTransfer public immutable PERMIT2;
    IIdentityRegistry public immutable identityRegistry;

    mapping(uint256 => Ticket) private _tickets;

    address public immutable reputationRegistry;

    uint256 private _nextTicketId = 1;

    error NotReputationRegistry();
    error InvalidRegistry();
    error InvalidPayment();
    error TicketNotMinted();
    error PayerMismatch();
    error PaymentTooEarly();
    error InvalidPermit2();
    error InvalidAgent();
    error InvalidMintAuthorization();

    modifier onlyReputationRegistry() {
        if (msg.sender != reputationRegistry) revert NotReputationRegistry();
        _;
    }

    /// @param permit2_ Canonical Permit2 address. Pass `address(0)` if Permit2 is not used on this chain.
    /// @param reputationRegistry_ ReputationRegistry proxy allowed to call `consumeTicket` (immutable).
    /// @param identityRegistry_ ERC-8004 identity registry; `agentId` must exist at mint time.
    constructor(address permit2_, address reputationRegistry_, address identityRegistry_)
        EIP712("ERC8004TicketMinter", "1")
    {
        if (reputationRegistry_ == address(0)) revert InvalidRegistry();
        if (identityRegistry_ == address(0)) revert InvalidRegistry();
        reputationRegistry = reputationRegistry_;
        identityRegistry = IIdentityRegistry(identityRegistry_);
        PERMIT2 = ISignatureTransfer(permit2_);
    }

    function settleAndMintTicketEIP3009(
        address payer,
        uint256 agentId,
        bytes32 requestHash,
        bytes32 interactionHash,
        string calldata endpoint,
        EIP3009Settlement calldata settlement
    ) external returns (uint256 ticketId) {
        if (payer == address(0) || settlement.token == address(0) || settlement.payTo == address(0) || settlement.value == 0) {
            revert InvalidPayment();
        }

        // Verify the payer's metadata authorization. EIP-3009's own signature binds only
        // token/to/value/nonce, NOT the ticket metadata — so we require a second payer
        // signature committing (agentId, requestHash, interactionHash, endpoint) to this
        // exact payment. This is what keeps permissionless minting trustless on this path.
        bytes32 metaHash = keccak256(
            abi.encode(
                TICKET_MINT_AUTHORIZATION_TYPEHASH,
                agentId,
                requestHash,
                interactionHash,
                keccak256(bytes(endpoint)),
                settlement.token,
                settlement.payTo,
                settlement.value,
                settlement.nonce
            )
        );
        if (_hashTypedDataV4(metaHash).recover(settlement.metadataSignature) != payer) {
            revert InvalidMintAuthorization();
        }

        // EIP-3009: payer signed an authorization to move `value` from `payer` to `payTo`.
        // Token contract checks the signature; we just forward the call.
        // Replay-safe: the token marks `nonce` used, so this whole call cannot be replayed.
        IERC3009(settlement.token).transferWithAuthorization(
            payer,
            settlement.payTo,
            settlement.value,
            settlement.validAfter,
            settlement.validBefore,
            settlement.nonce,
            settlement.signature
        );

        ticketId = _mintTicket(payer, agentId, requestHash, interactionHash, endpoint);
    }

    function settleAndMintTicketPermit2(
        address payer,
        uint256 agentId,
        bytes32 requestHash,
        bytes32 interactionHash,
        string calldata endpoint,
        Permit2Settlement calldata settlement
    ) external returns (uint256 ticketId) {
        if (address(PERMIT2) == address(0)) revert InvalidPermit2();
        if (
            payer == address(0) || settlement.payTo == address(0) || settlement.permit.permitted.token == address(0)
                || settlement.permit.permitted.amount == 0
        ) {
            revert InvalidPayment();
        }
        if (block.timestamp < settlement.validAfter) revert PaymentTooEarly();

        bytes32 witnessHash = keccak256(
            abi.encode(
                TICKET_WITNESS_TYPEHASH,
                payer,
                agentId,
                requestHash,
                interactionHash,
                keccak256(bytes(endpoint)),
                settlement.payTo,
                settlement.validAfter
            )
        );

        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer.SignatureTransferDetails({
            to: settlement.payTo,
            requestedAmount: settlement.permit.permitted.amount
        });

        PERMIT2.permitWitnessTransferFrom(
            settlement.permit,
            transferDetails,
            payer,
            witnessHash,
            TICKET_WITNESS_TYPE_STRING,
            settlement.signature
        );

        ticketId = _mintTicket(payer, agentId, requestHash, interactionHash, endpoint);
    }

    function consumeTicket(uint256 ticketId, address payer) external onlyReputationRegistry {
        Ticket storage ticket = _tickets[ticketId];
        if (ticket.status != TicketStatus.MINTED) revert TicketNotMinted();
        if (ticket.payer != payer) revert PayerMismatch();

        ticket.status = TicketStatus.CONSUMED;
        emit TicketConsumed(ticketId, payer);
    }

    function tickets(uint256 ticketId) external view returns (Ticket memory) {
        return _tickets[ticketId];
    }

    function nextTicketId() external view returns (uint256) {
        return _nextTicketId;
    }

    function _mintTicket(
        address payer,
        uint256 agentId,
        bytes32 requestHash,
        bytes32 interactionHash,
        string calldata endpoint
    ) internal returns (uint256 ticketId) {
        _requireAgentExists(agentId);

        ticketId = _nextTicketId++;
        _tickets[ticketId] = Ticket({
            payer: payer,
            agentId: agentId,
            requestHash: requestHash,
            interactionHash: interactionHash,
            endpoint: endpoint,
            status: TicketStatus.MINTED
        });

        emit TicketMinted(ticketId, payer, agentId, requestHash, interactionHash);
    }

    function _requireAgentExists(uint256 agentId) internal view {
        try identityRegistry.ownerOf(agentId) returns (address owner) {
            if (owner == address(0)) revert InvalidAgent();
        } catch {
            revert InvalidAgent();
        }
    }
}
