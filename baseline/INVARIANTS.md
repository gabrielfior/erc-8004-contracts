# Storage baseline — ReputationRegistryUpgradeable v2.0.0

Captured before the v3 (ticket-gated) upgrade. These are the **must-never-change**
invariants. Step 2 (storage gate) diffs v3 against the JSON files here.

Toolchain: Hardhat 3 + solc 0.8.24, viaIR + optimizer(200), evm=shanghai.

## Linear storage layout (`baseline/v2-storage-layout.json`)

Only ONE linear slot — everything else lives in the ERC-7201 namespace at a fixed
hashed slot (assembly-accessed, so solc does not report it as linear storage).

| slot | offset | name               | type    |
|------|--------|--------------------|---------|
| 0    | 0      | `_identityRegistry`| address |

INVARIANT: `_identityRegistry` MUST stay at slot 0 (shared with the MinimalUUPS
vanity placeholder). OwnableUpgradeable / UUPSUpgradeable / EIP712Upgradeable all
use their own ERC-7201 namespaces and do NOT add linear slots.

## ERC-7201 namespace location

INVARIANT: unchanged.
```
REPUTATION_REGISTRY_STORAGE_LOCATION =
  0xa03d7693f2b3746b2d03f163c788147b71aa82854399a21fdf4de143ba778300
// keccak256(abi.encode(uint256(keccak256("erc8004.reputation.registry.2")) - 1)) & ~bytes32(uint256(0xff))
```

## Feedback struct (`baseline/v2-struct-layout.json`)

| slot | offset | name           | type   | bytes |
|------|--------|----------------|--------|-------|
| 0    | 0      | `value`        | int128 | 16    |
| 0    | 16     | `valueDecimals`| uint8  | 1     |
| 0    | 17     | `isRevoked`    | bool   | 1     |
| 1    | 0      | `tag1`         | string | 32    |
| 2    | 0      | `tag2`         | string | 32    |

Slot 0 uses bytes 0–17; bytes 18–31 are free.
v3 PLAN: append `bool isDisputed` → slot 0 offset 18. Does NOT move tag1/tag2.

## ReputationRegistryStorage struct (`baseline/v2-struct-layout.json`)

| slot | name              |
|------|-------------------|
| 0    | `_feedback`       |
| 1    | `_lastIndex`      |
| 2    | `_responseCount`  |
| 3    | `_responders`     |
| 4    | `_responderExists`|
| 5    | `_clients`        |
| 6    | `_clientExists`   |

v3 PLAN: append `_ticketMinter` (slot 7), `_usedFeedbackHash` (slot 8),
`_feedbackNonces` (slot 9). Existing slots 0–6 unchanged.
