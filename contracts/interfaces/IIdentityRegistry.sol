// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal view surface of the ERC-8004 IdentityRegistry used by the
///         reputation system. The IdentityRegistry is ERC-721, so `ownerOf`
///         reverts (ERC721NonexistentToken) for unminted agents.
interface IIdentityRegistry {
    function ownerOf(uint256 agentId) external view returns (address);

    function isAuthorizedOrOwner(address spender, uint256 agentId) external view returns (bool);
}
