// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {IIdentityRegistry} from "./interfaces/IIdentityRegistry.sol";
import {ITicketMinter} from "./interfaces/ITicketMinter.sol";

/// @title ReputationRegistryUpgradeable (v3)
/// @notice ERC-8004 feedback registry. v3 keeps the original permissionless feedback path
///         intact and ADDS an optional, higher-trust x402 payment-gated path (ticket-backed),
///         agent-side disputes, and EIP-712 sponsored/relayed feedback submission.
/// @dev Storage is APPEND-ONLY relative to v2 — see baseline/INVARIANTS.md. `_identityRegistry`
///      stays at slot 0; the ERC-7201 namespace location is unchanged; new fields are appended
///      to `ReputationRegistryStorage` and the `Feedback` struct so all v2 feedback is preserved.
contract ReputationRegistryUpgradeable is OwnableUpgradeable, UUPSUpgradeable, EIP712Upgradeable {
    using ECDSA for bytes32;

    int128 private constant MAX_ABS_VALUE = 1e38;

    /// @dev EIP-712 typehash for relayed/sponsored feedback intents.
    bytes32 private constant FEEDBACK_INTENT_TYPEHASH = keccak256(
        "FeedbackIntent(uint256 ticketId,bytes32 interactionHash,int128 value,uint8 valueDecimals,bytes32 tag1Hash,bytes32 tag2Hash,bytes32 endpointHash,bytes32 feedbackURIHash,bytes32 feedbackHash,uint256 nonce,uint256 deadline)"
    );

    /// @notice Emitted for BOTH feedback paths. `ticketId == 0` ⇒ permissionless legacy path;
    ///         `ticketId > 0` ⇒ x402 payment-gated (ticket-backed) path.
    event NewFeedback(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 feedbackIndex,
        int128 value,
        uint8 valueDecimals,
        string indexed indexedTag1,
        string tag1,
        string tag2,
        string endpoint,
        string feedbackURI,
        bytes32 feedbackHash,
        uint256 ticketId
    );

    event FeedbackRevoked(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 indexed feedbackIndex
    );

    /// @notice Emitted when an authorized agent disputes a feedback record (distinct from client revocation).
    event FeedbackDisputed(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 indexed feedbackIndex
    );

    event ResponseAppended(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 feedbackIndex,
        address indexed responder,
        string responseURI,
        bytes32 responseHash
    );

    // --- v3 ticket-path errors ---
    error InvalidTicket();
    error InteractionHashMismatch();
    error SelfFeedbackNotAllowed();
    error FeedbackHashAlreadyUsed();
    error InvalidSignature();
    error IntentExpired();
    error InvalidNonce();
    error NotAgentAuthorized();
    error FeedbackNotFound();
    error AlreadyDisputed();
    error TicketMinterNotSet();

    struct Feedback {
        int128 value;          // slot 0, bytes 0-15  (existing)
        uint8 valueDecimals;   // slot 0, byte 16     (existing)
        bool isRevoked;        // slot 0, byte 17     (existing — client retraction)
        bool isDisputed;       // slot 0, byte 18     (v3 NEW — agent dispute; was zero for legacy records)
        string tag1;           // slot 1              (existing)
        string tag2;           // slot 2              (existing)
    }

    /// @dev Parameters for a relayed/sponsored ticket-gated submission (EIP-712 signed by `payer`).
    struct FeedbackSubmission {
        address payer;
        uint256 ticketId;
        bytes32 interactionHash;
        int128 value;
        uint8 valueDecimals;
        string tag1;
        string tag2;
        string endpoint;
        string feedbackURI;
        bytes32 feedbackHash;
    }

    /// @dev Identity registry address stored at slot 0 (matches MinimalUUPS). DO NOT MOVE.
    address private _identityRegistry;

    /// @custom:storage-location erc7201:erc8004.reputation.registry
    struct ReputationRegistryStorage {
        // agentId => clientAddress => feedbackIndex => Feedback (1-indexed)
        mapping(uint256 => mapping(address => mapping(uint64 => Feedback))) _feedback;
        // agentId => clientAddress => last feedback index
        mapping(uint256 => mapping(address => uint64)) _lastIndex;
        // agentId => clientAddress => feedbackIndex => responder => response count
        mapping(uint256 => mapping(address => mapping(uint64 => mapping(address => uint64)))) _responseCount;
        // Track all unique responders for each feedback
        mapping(uint256 => mapping(address => mapping(uint64 => address[]))) _responders;
        mapping(uint256 => mapping(address => mapping(uint64 => mapping(address => bool)))) _responderExists;
        // Track all unique clients that have given feedback for each agent
        mapping(uint256 => address[]) _clients;
        mapping(uint256 => mapping(address => bool)) _clientExists;
        // --- v3 additions (APPEND-ONLY) ---
        // x402 ticket minter paired with this registry
        address _ticketMinter;
        // agentId => payer => feedbackHash => used (replay protection for ticket-backed feedback)
        mapping(uint256 => mapping(address => mapping(bytes32 => bool))) _usedFeedbackHash;
        // payer => nonce => used (replay protection for sponsored intents)
        mapping(address => mapping(uint256 => bool)) _feedbackNonces;
    }

    // keccak256(abi.encode(uint256(keccak256("erc8004.reputation.registry.2")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant REPUTATION_REGISTRY_STORAGE_LOCATION =
        0xa03d7693f2b3746b2d03f163c788147b71aa82854399a21fdf4de143ba778300;

    function _getReputationRegistryStorage() private pure returns (ReputationRegistryStorage storage $) {
        assembly {
            $.slot := REPUTATION_REGISTRY_STORAGE_LOCATION
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice v2 initializer — retained for backward compatibility with existing deployments.
    function initialize(address identityRegistry_) public reinitializer(2) onlyOwner {
        require(identityRegistry_ != address(0), "bad identity");
        _identityRegistry = identityRegistry_;
    }

    /// @notice v3 initializer. Run via `upgradeToAndCall` during the upgrade. Sets the paired
    ///         TicketMinter and initializes EIP-712. `identityRegistry_` may be re-supplied (it is
    ///         already set for existing v2 proxies; pass address(0) to leave it untouched).
    function initializeV3(address identityRegistry_, address ticketMinter_) public reinitializer(3) onlyOwner {
        require(ticketMinter_ != address(0), "bad minter");
        __EIP712_init("ERC8004ReputationRegistry", "3");
        if (identityRegistry_ != address(0)) {
            _identityRegistry = identityRegistry_;
        }
        require(_identityRegistry != address(0), "identity not set");
        _getReputationRegistryStorage()._ticketMinter = ticketMinter_;
    }

    function getIdentityRegistry() external view returns (address) {
        return _identityRegistry;
    }

    function getTicketMinter() external view returns (address) {
        return _getReputationRegistryStorage()._ticketMinter;
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // ---------------------------------------------------------------------
    // Feedback submission
    // ---------------------------------------------------------------------

    /// @notice Permissionless feedback (legacy v2 path, unchanged behavior). Emits `ticketId == 0`.
    function giveFeedback(
        uint256 agentId,
        int128 value,
        uint8 valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata endpoint,
        string calldata feedbackURI,
        bytes32 feedbackHash
    ) external {
        _validateValue(value, valueDecimals);

        // SECURITY: Prevent self-feedback from owner and operators.
        // Also reverts with ERC721NonexistentToken if agent doesn't exist.
        require(!IIdentityRegistry(_identityRegistry).isAuthorizedOrOwner(msg.sender, agentId), "Self-feedback not allowed");

        _recordFeedback(agentId, msg.sender, value, valueDecimals, tag1, tag2, endpoint, feedbackURI, feedbackHash, 0);
    }

    /// @notice Higher-trust feedback backed by an x402 payment ticket. Caller is the payer.
    function giveFeedbackWithTicket(
        uint256 ticketId,
        int128 value,
        uint8 valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata endpoint,
        string calldata feedbackURI,
        bytes32 interactionHash,
        bytes32 feedbackHash
    ) external {
        _validateValue(value, valueDecimals);
        uint256 agentId = _consumeTicketForFeedback(msg.sender, ticketId, interactionHash, feedbackHash);
        _recordFeedback(agentId, msg.sender, value, valueDecimals, tag1, tag2, endpoint, feedbackURI, feedbackHash, ticketId);
    }

    /// @notice Relayed/sponsored ticket-backed feedback. `submission.payer` signs an EIP-712 intent;
    ///         anyone may relay it (gas sponsorship). Feedback is attributed to `payer`.
    function giveFeedbackWithTicketFor(
        FeedbackSubmission calldata submission,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external {
        _verifyFeedbackIntent(submission, nonce, deadline, signature);
        _validateValue(submission.value, submission.valueDecimals);
        uint256 agentId =
            _consumeTicketForFeedback(submission.payer, submission.ticketId, submission.interactionHash, submission.feedbackHash);
        _recordFeedback(
            agentId,
            submission.payer,
            submission.value,
            submission.valueDecimals,
            submission.tag1,
            submission.tag2,
            submission.endpoint,
            submission.feedbackURI,
            submission.feedbackHash,
            submission.ticketId
        );
    }

    // ---------------------------------------------------------------------
    // Moderation: client revoke (existing) + agent dispute (v3)
    // ---------------------------------------------------------------------

    function revokeFeedback(uint256 agentId, uint64 feedbackIndex) external {
        require(feedbackIndex > 0, "index must be > 0");
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        require(feedbackIndex <= $._lastIndex[agentId][msg.sender], "index out of bounds");
        require(!$._feedback[agentId][msg.sender][feedbackIndex].isRevoked, "Already revoked");

        $._feedback[agentId][msg.sender][feedbackIndex].isRevoked = true;
        emit FeedbackRevoked(agentId, msg.sender, feedbackIndex);
    }

    /// @notice An authorized agent (owner/operator) disputes a feedback record left against it.
    function disputeFeedback(uint256 agentId, address clientAddress, uint64 feedbackIndex) external {
        if (!IIdentityRegistry(_identityRegistry).isAuthorizedOrOwner(msg.sender, agentId)) revert NotAgentAuthorized();
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        if (feedbackIndex == 0 || feedbackIndex > $._lastIndex[agentId][clientAddress]) revert FeedbackNotFound();

        Feedback storage fb = $._feedback[agentId][clientAddress][feedbackIndex];
        if (fb.isDisputed) revert AlreadyDisputed();
        fb.isDisputed = true;

        emit FeedbackDisputed(agentId, clientAddress, feedbackIndex);
    }

    function appendResponse(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex,
        string calldata responseURI,
        bytes32 responseHash
    ) external {
        require(feedbackIndex > 0, "index must be > 0");
        require(bytes(responseURI).length > 0, "Empty URI");
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        require(feedbackIndex <= $._lastIndex[agentId][clientAddress], "index out of bounds");

        // Track new responder
        if (!$._responderExists[agentId][clientAddress][feedbackIndex][msg.sender]) {
            $._responders[agentId][clientAddress][feedbackIndex].push(msg.sender);
            $._responderExists[agentId][clientAddress][feedbackIndex][msg.sender] = true;
        }

        // Increment response count for this responder
        $._responseCount[agentId][clientAddress][feedbackIndex][msg.sender]++;

        emit ResponseAppended(agentId, clientAddress, feedbackIndex, msg.sender, responseURI, responseHash);
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    function getLastIndex(uint256 agentId, address clientAddress) external view returns (uint64) {
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        return $._lastIndex[agentId][clientAddress];
    }

    function readFeedback(uint256 agentId, address clientAddress, uint64 feedbackIndex)
        external
        view
        returns (int128 value, uint8 valueDecimals, string memory tag1, string memory tag2, bool isRevoked, bool isDisputed)
    {
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        require(feedbackIndex > 0, "index must be > 0");
        require(feedbackIndex <= $._lastIndex[agentId][clientAddress], "index out of bounds");
        Feedback storage f = $._feedback[agentId][clientAddress][feedbackIndex];
        return (f.value, f.valueDecimals, f.tag1, f.tag2, f.isRevoked, f.isDisputed);
    }

    function getSummary(
        uint256 agentId,
        address[] calldata clientAddresses,
        string calldata tag1,
        string calldata tag2
    ) external view returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals) {

        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        address[] memory clientList;
        if (clientAddresses.length > 0) {
            clientList = clientAddresses;
        } else {
            revert("clientAddresses required");
        }

        bytes32 emptyHash = keccak256(bytes(""));
        bytes32 tag1Hash = keccak256(bytes(tag1));
        bytes32 tag2Hash = keccak256(bytes(tag2));

        // WAD: 18 decimal fixed-point precision for internal math
        int256 sum;

        // Track frequency of each valueDecimals (0-18, anything >18 treated as 18)
        uint64[19] memory decimalCounts;

        for (uint256 i; i < clientList.length; i++) {
            uint64 lastIdx = $._lastIndex[agentId][clientList[i]];
            for (uint64 j = 1; j <= lastIdx; j++) {
                Feedback storage fb = $._feedback[agentId][clientList[i]][j];
                // Exclude both client-revoked and agent-disputed feedback from the aggregate.
                if (fb.isRevoked || fb.isDisputed) continue;
                if (emptyHash != tag1Hash &&
                    tag1Hash != keccak256(bytes(fb.tag1))) continue;
                if (emptyHash != tag2Hash &&
                    tag2Hash != keccak256(bytes(fb.tag2))) continue;

                // Normalize to 18 decimals (WAD)
                // `valueDecimals` is bounded to <= 18 on write; keep math signed.
                int256 factor = int256(10 ** uint256(18 - fb.valueDecimals));
                int256 normalized = fb.value * factor;
                decimalCounts[fb.valueDecimals]++;

                sum += normalized;
                count++;
            }
        }

        if (count == 0) {
            return (0, 0, 0);
        }

        // Find mode (most frequent valueDecimals)
        uint8 modeDecimals;
        uint64 maxCount;
        for (uint8 d; d <= 18; d++) {
            if (decimalCounts[d] > maxCount) {
                maxCount = decimalCounts[d];
                modeDecimals = d;
            }
        }

        // Calculate average in WAD, then scale to mode precision
        int256 avgWad = sum / int256(uint256(count));
        summaryValue = int128(avgWad / int256(10 ** uint256(18 - modeDecimals)));
        summaryValueDecimals = modeDecimals;
    }

    function readAllFeedback(
        uint256 agentId,
        address[] calldata clientAddresses,
        string calldata tag1,
        string calldata tag2,
        bool includeRevoked
    ) external view returns (
        address[] memory clients,
        uint64[] memory feedbackIndexes,
        int128[] memory values,
        uint8[] memory valueDecimals,
        string[] memory tag1s,
        string[] memory tag2s,
        bool[] memory revokedStatuses,
        bool[] memory disputedStatuses
    ) {
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        address[] memory clientList;
        if (clientAddresses.length > 0) {
            clientList = clientAddresses;
        } else {
            clientList = $._clients[agentId];
        }

        // First pass: count matching feedback
        bytes32 emptyHash = keccak256(bytes(""));
        bytes32 tag1Hash = keccak256(bytes(tag1));
        bytes32 tag2Hash = keccak256(bytes(tag2));
        uint256 totalCount;
        for (uint256 i; i < clientList.length; i++) {
            uint64 lastIdx = $._lastIndex[agentId][clientList[i]];
            for (uint64 j = 1; j <= lastIdx; j++) {
                Feedback storage fb = $._feedback[agentId][clientList[i]][j];
                if (!includeRevoked && fb.isRevoked) continue;
                if (emptyHash != tag1Hash &&
                    tag1Hash != keccak256(bytes(fb.tag1))) continue;
                if (emptyHash != tag2Hash &&
                    tag2Hash != keccak256(bytes(fb.tag2))) continue;
                totalCount++;
            }
        }

        // Initialize arrays
        clients = new address[](totalCount);
        feedbackIndexes = new uint64[](totalCount);
        values = new int128[](totalCount);
        valueDecimals = new uint8[](totalCount);
        tag1s = new string[](totalCount);
        tag2s = new string[](totalCount);
        revokedStatuses = new bool[](totalCount);
        disputedStatuses = new bool[](totalCount);

        // Second pass: populate arrays
        uint256 idx;
        for (uint256 i; i < clientList.length; i++) {
            uint64 lastIdx = $._lastIndex[agentId][clientList[i]];
            for (uint64 j = 1; j <= lastIdx; j++) {
                Feedback storage fb = $._feedback[agentId][clientList[i]][j];
                if (!includeRevoked && fb.isRevoked) continue;
                if (emptyHash != tag1Hash &&
                    tag1Hash != keccak256(bytes(fb.tag1))) continue;
                if (emptyHash != tag2Hash &&
                    tag2Hash != keccak256(bytes(fb.tag2))) continue;

                clients[idx] = clientList[i];
                feedbackIndexes[idx] = j;
                values[idx] = fb.value;
                valueDecimals[idx] = fb.valueDecimals;
                tag1s[idx] = fb.tag1;
                tag2s[idx] = fb.tag2;
                revokedStatuses[idx] = fb.isRevoked;
                disputedStatuses[idx] = fb.isDisputed;
                idx++;
            }
        }
    }

    function getResponseCount(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex,
        address[] calldata responders
    ) external view returns (uint64 count) {
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        if (clientAddress == address(0)) {
            // Count all responses for all clients
            address[] memory clients = $._clients[agentId];
            for (uint256 i; i < clients.length; i++) {
                uint64 lastIdx = $._lastIndex[agentId][clients[i]];
                for (uint64 j = 1; j <= lastIdx; j++) {
                    count += _countResponses(agentId, clients[i], j, responders);
                }
            }
        } else if (feedbackIndex == 0) {
            // Count all responses for specific clientAddress
            uint64 lastIdx = $._lastIndex[agentId][clientAddress];
            for (uint64 j = 1; j <= lastIdx; j++) {
                count += _countResponses(agentId, clientAddress, j, responders);
            }
        } else {
            // Count responses for specific clientAddress and feedbackIndex
            count = _countResponses(agentId, clientAddress, feedbackIndex, responders);
        }
    }

    function _countResponses(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex,
        address[] calldata responders
    ) internal view returns (uint64 count) {
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        if (responders.length == 0) {
            // Count from all responders
            address[] memory allResponders = $._responders[agentId][clientAddress][feedbackIndex];
            for (uint256 k; k < allResponders.length; k++) {
                count += $._responseCount[agentId][clientAddress][feedbackIndex][allResponders[k]];
            }
        } else {
            // Count from specified responders
            for (uint256 k; k < responders.length; k++) {
                count += $._responseCount[agentId][clientAddress][feedbackIndex][responders[k]];
            }
        }
    }

    function getClients(uint256 agentId) external view returns (address[] memory) {
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        return $._clients[agentId];
    }

    // ---------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------

    function _validateValue(int128 value, uint8 valueDecimals) internal pure {
        require(valueDecimals <= 18, "too many decimals");
        require(value >= -MAX_ABS_VALUE && value <= MAX_ABS_VALUE, "value too large");
    }

    /// @dev Shared write path for both permissionless and ticket-backed feedback.
    function _recordFeedback(
        uint256 agentId,
        address client,
        int128 value,
        uint8 valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata endpoint,
        string calldata feedbackURI,
        bytes32 feedbackHash,
        uint256 ticketId
    ) internal {
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();

        // Increment and get current index (1-indexed)
        uint64 currentIndex = ++$._lastIndex[agentId][client];

        $._feedback[agentId][client][currentIndex] = Feedback({
            value: value,
            valueDecimals: valueDecimals,
            isRevoked: false,
            isDisputed: false,
            tag1: tag1,
            tag2: tag2
        });

        // track new client
        if (!$._clientExists[agentId][client]) {
            $._clients[agentId].push(client);
            $._clientExists[agentId][client] = true;
        }

        emit NewFeedback(agentId, client, currentIndex, value, valueDecimals, tag1, tag1, tag2, endpoint, feedbackURI, feedbackHash, ticketId);
    }

    /// @dev Validates and consumes an x402 ticket, returning the agentId it was minted for.
    function _consumeTicketForFeedback(address payer, uint256 ticketId, bytes32 interactionHash, bytes32 feedbackHash)
        internal
        returns (uint256 agentId)
    {
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        address minter = $._ticketMinter;
        if (minter == address(0)) revert TicketMinterNotSet();

        ITicketMinter.Ticket memory ticket = ITicketMinter(minter).tickets(ticketId);
        if (ticket.status != ITicketMinter.TicketStatus.MINTED) revert InvalidTicket();
        if (ticket.payer != payer) revert InvalidTicket();
        if (ticket.interactionHash != interactionHash) revert InteractionHashMismatch();
        if (IIdentityRegistry(_identityRegistry).isAuthorizedOrOwner(payer, ticket.agentId)) revert SelfFeedbackNotAllowed();
        if ($._usedFeedbackHash[ticket.agentId][payer][feedbackHash]) revert FeedbackHashAlreadyUsed();

        $._usedFeedbackHash[ticket.agentId][payer][feedbackHash] = true;
        ITicketMinter(minter).consumeTicket(ticketId, payer);
        return ticket.agentId;
    }

    function _verifyFeedbackIntent(
        FeedbackSubmission calldata submission,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) internal {
        if (block.timestamp > deadline) revert IntentExpired();
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        if ($._feedbackNonces[submission.payer][nonce]) revert InvalidNonce();

        bytes32 structHash = keccak256(
            abi.encode(
                FEEDBACK_INTENT_TYPEHASH,
                submission.ticketId,
                submission.interactionHash,
                submission.value,
                submission.valueDecimals,
                keccak256(bytes(submission.tag1)),
                keccak256(bytes(submission.tag2)),
                keccak256(bytes(submission.endpoint)),
                keccak256(bytes(submission.feedbackURI)),
                submission.feedbackHash,
                nonce,
                deadline
            )
        );

        address recovered = _hashTypedDataV4(structHash).recover(signature);
        if (recovered != submission.payer) revert InvalidSignature();
        $._feedbackNonces[submission.payer][nonce] = true;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function getVersion() external pure returns (string memory) {
        return "3.0.0";
    }
}
