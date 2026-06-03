// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// TEST FIXTURE: a byte-for-byte snapshot of ReputationRegistryUpgradeable v2.0.0,
// renamed to avoid artifact collisions. Used by test/upgrade-v3.ts to seed real
// v2 storage, then upgrade the proxy to the v3 implementation and prove existing
// feedback survives. NOT part of the deployed system.

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

interface IIdentityRegistry {
    function isAuthorizedOrOwner(address spender, uint256 agentId) external view returns (bool);
}

contract ReputationRegistryV2Frozen is OwnableUpgradeable, UUPSUpgradeable {

    int128 private constant MAX_ABS_VALUE = 1e38;

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
        bytes32 feedbackHash
    );

    event FeedbackRevoked(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 indexed feedbackIndex
    );

    struct Feedback {
        int128 value;
        uint8 valueDecimals;
        bool isRevoked;
        string tag1;
        string tag2;
    }

    /// @dev Identity registry address stored at slot 0 (matches MinimalUUPS)
    address private _identityRegistry;

    /// @custom:storage-location erc7201:erc8004.reputation.registry
    struct ReputationRegistryStorage {
        mapping(uint256 => mapping(address => mapping(uint64 => Feedback))) _feedback;
        mapping(uint256 => mapping(address => uint64)) _lastIndex;
        mapping(uint256 => mapping(address => mapping(uint64 => mapping(address => uint64)))) _responseCount;
        mapping(uint256 => mapping(address => mapping(uint64 => address[]))) _responders;
        mapping(uint256 => mapping(address => mapping(uint64 => mapping(address => bool)))) _responderExists;
        mapping(uint256 => address[]) _clients;
        mapping(uint256 => mapping(address => bool)) _clientExists;
    }

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

    function initialize(address identityRegistry_) public reinitializer(2) onlyOwner {
        require(identityRegistry_ != address(0), "bad identity");
        _identityRegistry = identityRegistry_;
    }

    function getIdentityRegistry() external view returns (address) {
        return _identityRegistry;
    }

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
        require(valueDecimals <= 18, "too many decimals");
        require(value >= -MAX_ABS_VALUE && value <= MAX_ABS_VALUE, "value too large");
        require(!IIdentityRegistry(_identityRegistry).isAuthorizedOrOwner(msg.sender, agentId), "Self-feedback not allowed");

        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        uint64 currentIndex = ++$._lastIndex[agentId][msg.sender];

        $._feedback[agentId][msg.sender][currentIndex] = Feedback({
            value: value,
            valueDecimals: valueDecimals,
            tag1: tag1,
            tag2: tag2,
            isRevoked: false
        });

        if (!$._clientExists[agentId][msg.sender]) {
            $._clients[agentId].push(msg.sender);
            $._clientExists[agentId][msg.sender] = true;
        }

        emit NewFeedback(agentId, msg.sender, currentIndex, value, valueDecimals, tag1, tag1, tag2, endpoint, feedbackURI, feedbackHash);
    }

    function revokeFeedback(uint256 agentId, uint64 feedbackIndex) external {
        require(feedbackIndex > 0, "index must be > 0");
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        require(feedbackIndex <= $._lastIndex[agentId][msg.sender], "index out of bounds");
        require(!$._feedback[agentId][msg.sender][feedbackIndex].isRevoked, "Already revoked");

        $._feedback[agentId][msg.sender][feedbackIndex].isRevoked = true;
        emit FeedbackRevoked(agentId, msg.sender, feedbackIndex);
    }

    function getLastIndex(uint256 agentId, address clientAddress) external view returns (uint64) {
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        return $._lastIndex[agentId][clientAddress];
    }

    function readFeedback(uint256 agentId, address clientAddress, uint64 feedbackIndex)
        external
        view
        returns (int128 value, uint8 valueDecimals, string memory tag1, string memory tag2, bool isRevoked)
    {
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        require(feedbackIndex > 0, "index must be > 0");
        require(feedbackIndex <= $._lastIndex[agentId][clientAddress], "index out of bounds");
        Feedback storage f = $._feedback[agentId][clientAddress][feedbackIndex];
        return (f.value, f.valueDecimals, f.tag1, f.tag2, f.isRevoked);
    }

    function getClients(uint256 agentId) external view returns (address[] memory) {
        ReputationRegistryStorage storage $ = _getReputationRegistryStorage();
        return $._clients[agentId];
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function getVersion() external pure returns (string memory) {
        return "2.0.0";
    }
}
