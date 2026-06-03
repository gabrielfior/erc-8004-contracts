import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { encodeAbiParameters, encodeFunctionData, keccak256, toHex, getAddress, zeroAddress } from "viem";

// Step 3 — Data-survival gate.
// Seeds real v2 storage (via the frozen v2 implementation), upgrades the proxy to
// the v3 implementation, and proves every pre-existing feedback record survives
// byte-for-byte. Then exercises the new ticket-gated path and agent disputes.
describe("ReputationRegistry v2 -> v3 upgrade", async function () {
  const { viem } = await network.connect();
  const publicClient = await viem.getPublicClient();

  async function getAgentIdFromRegistration(txHash: `0x${string}`) {
    const receipt = await publicClient.getTransactionReceipt({ hash: txHash });
    const log = receipt.logs.find(l => l.topics[0] === keccak256(toHex("Registered(uint256,string,address)")));
    if (!log || !log.topics[1]) throw new Error("Registered event not found");
    return BigInt(log.topics[1]);
  }

  function encodeInitializeWithAddress(addr: `0x${string}`): `0x${string}` {
    const params = encodeAbiParameters([{ type: "address" }], [addr]);
    return ("0xc4d66de8" + params.slice(2)) as `0x${string}`;
  }

  async function deployProxy(impl: `0x${string}`, initCalldata: `0x${string}`) {
    return await viem.deployContract("ERC1967Proxy", [impl, initCalldata]);
  }

  async function deployIdentityRegistryProxy() {
    const minimalImpl = await viem.deployContract("HardhatMinimalUUPS");
    const proxy = await deployProxy(minimalImpl.address, encodeInitializeWithAddress(zeroAddress));
    const realImpl = await viem.deployContract("IdentityRegistryUpgradeable");
    const minimalProxy = await viem.getContractAt("HardhatMinimalUUPS", proxy.address);
    await minimalProxy.write.upgradeToAndCall([realImpl.address, "0x8129fc1c"]);
    return await viem.getContractAt("IdentityRegistryUpgradeable", proxy.address);
  }

  // Deploy a Reputation proxy running the FROZEN v2 implementation.
  async function deployReputationV2FrozenProxy(identityAddr: `0x${string}`) {
    const minimalImpl = await viem.deployContract("HardhatMinimalUUPS");
    const proxy = await deployProxy(minimalImpl.address, encodeInitializeWithAddress(identityAddr));
    const v2Impl = await viem.deployContract("ReputationRegistryV2Frozen");
    const minimalProxy = await viem.getContractAt("HardhatMinimalUUPS", proxy.address);
    await minimalProxy.write.upgradeToAndCall([v2Impl.address, encodeInitializeWithAddress(identityAddr)]);
    return await viem.getContractAt("ReputationRegistryV2Frozen", proxy.address);
  }

  it("preserves all v2 feedback after upgrading to v3 and enables the ticket path", async function () {
    const [owner, client1, client2, payer] = await viem.getWalletClients();

    const identity = await deployIdentityRegistryProxy();
    const txHash = await identity.write.register(["ipfs://agent"], { account: owner.account });
    const agentId = await getAgentIdFromRegistration(txHash);

    const v2 = await deployReputationV2FrozenProxy(identity.address);
    const proxyAddr = v2.address;

    // --- Seed real v2 storage ---
    const fh = (s: string) => keccak256(toHex(s));
    await v2.write.giveFeedback(
      [agentId, 80n, 0, "quality", "fast", "https://e1", "ipfs://f1", fh("f1")],
      { account: client1.account });
    await v2.write.giveFeedback(
      [agentId, 60n, 0, "quality", "slow", "https://e2", "ipfs://f2", fh("f2")],
      { account: client1.account });
    await v2.write.giveFeedback(
      [agentId, 90n, 0, "quality", "fast", "https://e3", "ipfs://f3", fh("f3")],
      { account: client2.account });
    // client1 revokes their 2nd feedback
    await v2.write.revokeFeedback([agentId, 2n], { account: client1.account });

    // Capture pre-upgrade state
    const clientsBefore = await v2.read.getClients([agentId]);
    const lastIdxC1Before = await v2.read.getLastIndex([agentId, client1.account.address]);

    // --- Upgrade to v3 (atomic upgradeToAndCall -> initializeV3) ---
    const v3Impl = await viem.deployContract("ReputationRegistryUpgradeable");
    // Deploy the paired minter bound to THIS proxy (immutable reputationRegistry).
    const minter = await viem.deployContract("TicketMinter",
      [owner.account.address, zeroAddress, proxyAddr, identity.address]);

    // Pass zeroAddress for identity to prove it persisted across the upgrade.
    const initV3 = encodeFunctionData({
      abi: v3Impl.abi,
      functionName: "initializeV3",
      args: [zeroAddress, minter.address],
    });
    await v2.write.upgradeToAndCall([v3Impl.address, initV3], { account: owner.account });

    const v3 = await viem.getContractAt("ReputationRegistryUpgradeable", proxyAddr);

    // --- Gate assertions: identity, version, minter ---
    assert.equal(await v3.read.getVersion(), "3.0.0");
    assert.equal((await v3.read.getIdentityRegistry()).toLowerCase(), identity.address.toLowerCase());
    assert.equal((await v3.read.getTicketMinter()).toLowerCase(), minter.address.toLowerCase());

    // --- Gate assertions: every v2 record survives byte-for-byte ---
    const f1 = await v3.read.readFeedback([agentId, client1.account.address, 1n]);
    assert.equal(f1[0], 80n);            // value
    assert.equal(f1[1], 0);              // valueDecimals
    assert.equal(f1[2], "quality");      // tag1
    assert.equal(f1[3], "fast");         // tag2
    assert.equal(f1[4], false);          // isRevoked (preserved)
    assert.equal(f1[5], false);          // isDisputed (new field defaults false)

    const f2 = await v3.read.readFeedback([agentId, client1.account.address, 2n]);
    assert.equal(f2[0], 60n);
    assert.equal(f2[2], "quality");
    assert.equal(f2[3], "slow");
    assert.equal(f2[4], true);           // isRevoked preserved across upgrade
    assert.equal(f2[5], false);

    const f3 = await v3.read.readFeedback([agentId, client2.account.address, 1n]);
    assert.equal(f3[0], 90n);
    assert.equal(f3[4], false);

    // Client list + indexes preserved
    const clientsAfter = await v3.read.getClients([agentId]);
    assert.deepEqual(clientsAfter.map(a => a.toLowerCase()), clientsBefore.map(a => a.toLowerCase()));
    assert.equal(await v3.read.getLastIndex([agentId, client1.account.address]), lastIdxC1Before);

    // --- Permissionless path still works post-upgrade ---
    await v3.write.giveFeedback(
      [agentId, 70n, 0, "quality", "ok", "https://e4", "ipfs://f4", fh("f4")],
      { account: client1.account });
    const f4 = await v3.read.readFeedback([agentId, client1.account.address, 3n]);
    assert.equal(f4[0], 70n);
    assert.equal(f4[5], false);

    // --- New ticket-gated path ---
    const token = await viem.deployContract("MockERC20");
    await token.write.mint([payer.account.address, 1000n]);
    await token.write.approve([minter.address, 1000n], { account: payer.account });
    await minter.write.setFacilitator([owner.account.address, true], { account: owner.account });

    const minterTyped = await viem.getContractAt("TicketMinter", minter.address);
    const ticketId = await minterTyped.read.nextTicketId(); // id that will be assigned
    const requestHash = fh("req");
    const interactionHash = fh("interaction");
    const feedbackHash = fh("ticket-fb");
    await minterTyped.write.settleAndMintTicket(
      [payer.account.address, agentId, requestHash, interactionHash, "https://svc",
        { token: token.address, payTo: owner.account.address, amount: 1000n }],
      { account: owner.account });

    // Payer submits ticket-backed feedback
    await v3.write.giveFeedbackWithTicket(
      [ticketId, 100n, 0, "quality", "ticketed", "https://svc", "ipfs://tf", interactionHash, feedbackHash],
      { account: payer.account });

    const tf = await v3.read.readFeedback([agentId, payer.account.address, 1n]);
    assert.equal(tf[0], 100n);
    assert.equal(tf[3], "ticketed");
    assert.equal(tf[5], false);

    // Replay with the now-consumed ticket must revert
    await assert.rejects(
      v3.write.giveFeedbackWithTicket(
        [ticketId, 100n, 0, "quality", "ticketed", "https://svc", "ipfs://tf", interactionHash, fh("other")],
        { account: payer.account }));

    // --- Agent dispute ---
    // Summary over payer before dispute: 1 record counted
    const sumBefore = await v3.read.getSummary([agentId, [payer.account.address], "", ""]);
    assert.equal(sumBefore[0], 1n);

    await v3.write.disputeFeedback([agentId, payer.account.address, 1n], { account: owner.account });
    const tfDisputed = await v3.read.readFeedback([agentId, payer.account.address, 1n]);
    assert.equal(tfDisputed[5], true); // isDisputed

    // Disputed feedback excluded from summary
    const sumAfter = await v3.read.getSummary([agentId, [payer.account.address], "", ""]);
    assert.equal(sumAfter[0], 0n);
  });
});
