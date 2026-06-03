# Step 2 — Storage compatibility gate: PASS

Static verification that v3 storage is strictly append-only vs the v2 baseline
(see `INVARIANTS.md`). The dynamic proof is the Step 3 Hardhat test
(`test/upgrade-v3.ts`), which upgrades a real proxy and re-reads pre-existing
feedback.

## Result

**Linear layout** — unchanged:

| slot | offset | field              |
|------|--------|--------------------|
| 0    | 0      | `_identityRegistry`|

(OwnableUpgradeable / UUPSUpgradeable / EIP712Upgradeable all use their own
ERC-7201 namespaces — they add no linear slots.)

**`Feedback` struct** — every v2 field fixed in place; `isDisputed` added into
slot-0 free space:

| slot | offset | field          | status   |
|------|--------|----------------|----------|
| 0    | 0      | `value`        | v2       |
| 0    | 16     | `valueDecimals`| v2       |
| 0    | 17     | `isRevoked`    | v2       |
| 0    | 18     | `isDisputed`   | **v3 new** (was zero) |
| 1    | 0      | `tag1`         | v2 (unchanged) |
| 2    | 0      | `tag2`         | v2 (unchanged) |

**`ReputationRegistryStorage`** — slots 0–6 unchanged; appended at 7–9:

| slot | field              | status |
|------|--------------------|--------|
| 0–6  | (v2 mappings)      | v2     |
| 7    | `_ticketMinter`    | v3 new |
| 8    | `_usedFeedbackHash`| v3 new |
| 9    | `_feedbackNonces`  | v3 new |

ERC-7201 namespace location constant unchanged:
`0xa03d7693f2b3746b2d03f163c788147b71aa82854399a21fdf4de143ba778300`.

## How to reproduce

The namespaced struct is assembly-accessed, so solc does not emit its layout for
the contract directly. To re-verify, drop a probe contract into `contracts/` that
declares the `Feedback` and `ReputationRegistryStorage` structs as real state
variables, compile with `outputSelection: { "*": { "*": ["storageLayout"] } }`
(already set in `hardhat.config.ts`), read the struct member layout from
`artifacts/build-info/*.output.json`, and assert every v2 `(slot,offset,label)`
in `baseline/v2-struct-layout.json` is present unchanged. Delete the probe after.
