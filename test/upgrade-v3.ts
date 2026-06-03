import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { encodeAbiParameters, encodeFunctionData, keccak256, toHex, zeroAddress } from "viem";

// v3 (ticket-gated) test suite.
//  - "v2 -> v3 upgrade": data-survival gate (Step 3) — existing feedback survives byte-for-byte.
//  - feature suites: ticket-gated feedback (EIP-3009), sponsored feedback, disputes.
// Permit2 settlement is exercised by x402's own tests and is not re-covered here.
describe("ReputationRegistry v3", async function () {
  const { viem } = await network.connect();
  const publicClient = await viem.getPublicClient();
  const chainId = await publicClient.getChainId();
  const fh = (s: string) => keccak256(toHex(s));
  const VALID_BEFORE = 99999999999n; // far future

  async function getAgentIdFromRegistration(txHash: `0x${string}`) {
    const receipt = await publicClient.getTransactionReceipt({ hash: txHash });
    const log = receipt.logs.find(l => l.topics[0] === keccak256(toHex("Registered(uint256,string,address)")));
    if (!log || !log.topics[1]) throw new Error("Registered event not found");
    return BigInt(log.topics[1]);
  }

  function encodeInitializeWithAddress(addr: `0x${string}`): `0x${string}` {
    return ("0xc4d66de8" + encodeAbiParameters([{ type: "address" }], [addr]).slice(2)) as `0x${string}`;
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

  async function deployReputationV2FrozenProxy(identityAddr: `0x${string}`) {
    const minimalImpl = await viem.deployContract("HardhatMinimalUUPS");
    const proxy = await deployProxy(minimalImpl.address, encodeInitializeWithAddress(identityAddr));
    const v2Impl = await viem.deployContract("ReputationRegistryV2Frozen");
    const minimalProxy = await viem.getContractAt("HardhatMinimalUUPS", proxy.address);
    await minimalProxy.write.upgradeToAndCall([v2Impl.address, encodeInitializeWithAddress(identityAddr)]);
    return await viem.getContractAt("ReputationRegistryV2Frozen", proxy.address);
  }

  // Fresh v3 deployment (MinimalUUPS -> v3 impl + initializeV3). `withMinter=false` leaves the
  // ticket minter unset (proxy upgraded with empty calldata) for the TicketMinterNotSet case.
  async function deployV3(withMinter = true) {
    const identity = await deployIdentityRegistryProxy();
    const minimalImpl = await viem.deployContract("HardhatMinimalUUPS");
    const proxy = await deployProxy(minimalImpl.address, encodeInitializeWithAddress(identity.address));
    const v3Impl = await viem.deployContract("ReputationRegistryUpgradeable");
    const minter = await viem.deployContract("TicketMinter", [zeroAddress, proxy.address, identity.address]);
    const minimalProxy = await viem.getContractAt("HardhatMinimalUUPS", proxy.address);
    if (withMinter) {
      const initV3 = encodeFunctionData({ abi: v3Impl.abi, functionName: "initializeV3", args: [identity.address, minter.address] });
      await minimalProxy.write.upgradeToAndCall([v3Impl.address, initV3]);
    } else {
      await minimalProxy.write.upgradeToAndCall([v3Impl.address, "0x"]);
    }
    const v3 = await viem.getContractAt("ReputationRegistryUpgradeable", proxy.address);
    const minterTyped = await viem.getContractAt("TicketMinter", minter.address);
    return { v3, minter: minterTyped, identity, proxyAddr: proxy.address as `0x${string}`, token: await deployToken() };
  }

  async function deployToken() {
    return await viem.deployContract("MockERC3009");
  }

  // -------------------------------------------------------------------------
  describe("v2 -> v3 upgrade (data survival)", function () {
    it("preserves all v2 feedback byte-for-byte and keeps the permissionless path working", async function () {
      const [owner, client1, client2] = await viem.getWalletClients();

      const identity = await deployIdentityRegistryProxy();
      const agentId = await getAgentIdFromRegistration(
        await identity.write.register(["ipfs://agent"], { account: owner.account }));

      const v2 = await deployReputationV2FrozenProxy(identity.address);
      const proxyAddr = v2.address;

      await v2.write.giveFeedback([agentId, 80n, 0, "quality", "fast", "https://e1", "ipfs://f1", fh("f1")], { account: client1.account });
      await v2.write.giveFeedback([agentId, 60n, 0, "quality", "slow", "https://e2", "ipfs://f2", fh("f2")], { account: client1.account });
      await v2.write.giveFeedback([agentId, 90n, 0, "quality", "fast", "https://e3", "ipfs://f3", fh("f3")], { account: client2.account });
      await v2.write.revokeFeedback([agentId, 2n], { account: client1.account });

      const clientsBefore = await v2.read.getClients([agentId]);
      const lastIdxC1Before = await v2.read.getLastIndex([agentId, client1.account.address]);

      // Upgrade: deploy v3 impl + paired minter, then atomic upgradeToAndCall(initializeV3).
      const v3Impl = await viem.deployContract("ReputationRegistryUpgradeable");
      const minter = await viem.deployContract("TicketMinter", [zeroAddress, proxyAddr, identity.address]);
      // Pass zeroAddress for identity to prove it persisted across the upgrade.
      const initV3 = encodeFunctionData({ abi: v3Impl.abi, functionName: "initializeV3", args: [zeroAddress, minter.address] });
      await v2.write.upgradeToAndCall([v3Impl.address, initV3], { account: owner.account });
      const v3 = await viem.getContractAt("ReputationRegistryUpgradeable", proxyAddr);

      assert.equal(await v3.read.getVersion(), "3.0.0");
      assert.equal((await v3.read.getIdentityRegistry()).toLowerCase(), identity.address.toLowerCase());
      assert.equal((await v3.read.getTicketMinter()).toLowerCase(), minter.address.toLowerCase());

      const f1 = await v3.read.readFeedback([agentId, client1.account.address, 1n]);
      assert.deepEqual([f1[0], f1[1], f1[2], f1[3], f1[4], f1[5]], [80n, 0, "quality", "fast", false, false]);
      const f2 = await v3.read.readFeedback([agentId, client1.account.address, 2n]);
      assert.equal(f2[4], true);  // isRevoked preserved
      assert.equal(f2[5], false); // isDisputed defaults false
      const f3 = await v3.read.readFeedback([agentId, client2.account.address, 1n]);
      assert.equal(f3[0], 90n);

      const clientsAfter = await v3.read.getClients([agentId]);
      assert.deepEqual(clientsAfter.map(a => a.toLowerCase()), clientsBefore.map(a => a.toLowerCase()));
      assert.equal(await v3.read.getLastIndex([agentId, client1.account.address]), lastIdxC1Before);

      // Permissionless path still works post-upgrade
      await v3.write.giveFeedback([agentId, 70n, 0, "quality", "ok", "https://e4", "ipfs://f4", fh("f4")], { account: client1.account });
      assert.equal((await v3.read.readFeedback([agentId, client1.account.address, 3n]))[0], 70n);
    });
  });

  // -------------------------------------------------------------------------
  describe("ticket-gated feedback (EIP-3009, permissionless mint)", function () {
    async function setup() {
      const [owner, payer, relayer] = await viem.getWalletClients();
      const { v3, minter, identity, token } = await deployV3();
      const agentId = await getAgentIdFromRegistration(
        await identity.write.register(["ipfs://agent"], { account: owner.account }));
      return { owner, payer, relayer, v3, minter, identity, token, agentId };
    }
    const baseOpts = (over: any = {}) => ({
      requestHash: fh("req"), interactionHash: fh("interaction"),
      payTo: "0x000000000000000000000000000000000000dEaD" as `0x${string}`,
      value: 1000n, nonce: fh("n1"), endpoint: "https://svc", ...over,
    });

    it("records feedback minted by a third-party relayer", async function () {
      const { payer, relayer, v3, minter, token, agentId } = await setup();
      const opts = baseOpts();
      const ticketId = await mintTicketWith(minter, token, payer, relayer, agentId, opts);
      await v3.write.giveFeedbackWithTicket(
        [ticketId, 100n, 0, "quality", "ticketed", opts.endpoint, "ipfs://tf", opts.interactionHash, fh("fb")],
        { account: payer.account });
      const tf = await v3.read.readFeedback([agentId, payer.account.address, 1n]);
      assert.equal(tf[0], 100n);
      assert.equal(tf[3], "ticketed");
      assert.equal(tf[5], false);
    });

    it("rejects re-attribution of the payment to another agent", async function () {
      const { payer, relayer, minter, token, agentId } = await setup();
      const opts = baseOpts();
      // Sign metadata for `agentId` but try to mint for agentId+1 → InvalidMintAuthorization.
      await token.write.mint([payer.account.address, opts.value]);
      const eip3009Sig = await signTransfer(payer, token, opts);
      const metadataSig = await signMetadata(payer, minter, agentId, token, opts);
      await assert.rejects(minter.write.settleAndMintTicketEIP3009(
        [payer.account.address, agentId + 1n, opts.requestHash, opts.interactionHash, opts.endpoint,
          settlement(token, opts, eip3009Sig, metadataSig)], { account: relayer.account }));
    });

    it("rejects replay of a consumed ticket", async function () {
      const { payer, relayer, v3, minter, token, agentId } = await setup();
      const opts = baseOpts();
      const ticketId = await mintTicketWith(minter, token, payer, relayer, agentId, opts);
      await v3.write.giveFeedbackWithTicket([ticketId, 100n, 0, "q", "t", opts.endpoint, "ipfs://tf", opts.interactionHash, fh("fb1")], { account: payer.account });
      await assert.rejects(v3.write.giveFeedbackWithTicket([ticketId, 100n, 0, "q", "t", opts.endpoint, "ipfs://tf", opts.interactionHash, fh("fb2")], { account: payer.account }));
    });

    it("rejects a duplicate feedbackHash across two tickets (dedup)", async function () {
      const { payer, relayer, v3, minter, token, agentId } = await setup();
      const t1 = await mintTicketWith(minter, token, payer, relayer, agentId, baseOpts({ nonce: fh("nA"), interactionHash: fh("iA") }));
      const t2 = await mintTicketWith(minter, token, payer, relayer, agentId, baseOpts({ nonce: fh("nB"), interactionHash: fh("iB") }));
      const dupHash = fh("dup");
      await v3.write.giveFeedbackWithTicket([t1, 100n, 0, "q", "t", "https://svc", "ipfs://tf", fh("iA"), dupHash], { account: payer.account });
      await assert.rejects(v3.write.giveFeedbackWithTicket([t2, 100n, 0, "q", "t", "https://svc", "ipfs://tf", fh("iB"), dupHash], { account: payer.account }));
    });

    it("rejects interactionHash mismatch", async function () {
      const { payer, relayer, v3, minter, token, agentId } = await setup();
      const t = await mintTicketWith(minter, token, payer, relayer, agentId, baseOpts({ interactionHash: fh("real") }));
      await assert.rejects(v3.write.giveFeedbackWithTicket([t, 100n, 0, "q", "t", "https://svc", "ipfs://tf", fh("wrong"), fh("fb")], { account: payer.account }));
    });

    it("rejects self-feedback by the agent owner", async function () {
      const [owner] = await viem.getWalletClients();
      const { v3, minter, identity, token } = await deployV3();
      const agentId = await getAgentIdFromRegistration(await identity.write.register(["ipfs://agent"], { account: owner.account }));
      // owner is the agent owner; mint a ticket for owner then attempt self-feedback.
      const t = await mintTicketWith(minter, token, owner, owner, agentId, baseOpts({ nonce: fh("self") }));
      await assert.rejects(v3.write.giveFeedbackWithTicket([t, 100n, 0, "q", "t", "https://svc", "ipfs://tf", fh("interaction"), fh("fb")], { account: owner.account }));
    });

    it("reverts when the ticket minter is not set", async function () {
      const [owner, payer] = await viem.getWalletClients();
      const { v3 } = await deployV3(false); // upgraded without initializeV3 → minter unset
      await assert.rejects(v3.write.giveFeedbackWithTicket([1n, 100n, 0, "q", "t", "https://svc", "ipfs://tf", fh("i"), fh("fb")], { account: payer.account }));
    });
  });

  // -------------------------------------------------------------------------
  describe("sponsored feedback (giveFeedbackWithTicketFor)", function () {
    async function setupWithTicket() {
      const [owner, payer, relayer] = await viem.getWalletClients();
      const { v3, minter, identity, token, proxyAddr } = await deployV3();
      const agentId = await getAgentIdFromRegistration(await identity.write.register(["ipfs://agent"], { account: owner.account }));
      const opts = { requestHash: fh("req"), interactionHash: fh("interaction"), payTo: "0x000000000000000000000000000000000000dEaD" as `0x${string}`, value: 1000n, nonce: fh("n1"), endpoint: "https://svc" };
      const ticketId = await mintTicketWith(minter, token, payer, relayer, agentId, opts);
      return { owner, payer, relayer, v3, agentId, proxyAddr, ticketId, opts };
    }

    function submission(payer: any, ticketId: bigint, opts: any, over: any = {}) {
      return { payer: payer.account.address, ticketId, interactionHash: opts.interactionHash, value: 100n, valueDecimals: 0, tag1: "q", tag2: "t", endpoint: opts.endpoint, feedbackURI: "ipfs://tf", feedbackHash: fh("fb"), ...over };
    }

    async function signIntent(payer: any, proxyAddr: `0x${string}`, sub: any, nonce: bigint, deadline: bigint) {
      return await payer.signTypedData({
        domain: { name: "ERC8004ReputationRegistry", version: "3", chainId, verifyingContract: proxyAddr },
        types: { FeedbackIntent: [
          { name: "ticketId", type: "uint256" }, { name: "interactionHash", type: "bytes32" }, { name: "value", type: "int128" },
          { name: "valueDecimals", type: "uint8" }, { name: "tag1Hash", type: "bytes32" }, { name: "tag2Hash", type: "bytes32" },
          { name: "endpointHash", type: "bytes32" }, { name: "feedbackURIHash", type: "bytes32" }, { name: "feedbackHash", type: "bytes32" },
          { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" },
        ] },
        primaryType: "FeedbackIntent",
        message: {
          ticketId: sub.ticketId, interactionHash: sub.interactionHash, value: sub.value, valueDecimals: sub.valueDecimals,
          tag1Hash: keccak256(toHex(sub.tag1)), tag2Hash: keccak256(toHex(sub.tag2)), endpointHash: keccak256(toHex(sub.endpoint)),
          feedbackURIHash: keccak256(toHex(sub.feedbackURI)), feedbackHash: sub.feedbackHash, nonce, deadline,
        },
      });
    }

    it("lets a relayer submit a payer-signed intent", async function () {
      const { payer, relayer, v3, agentId, proxyAddr, ticketId, opts } = await setupWithTicket();
      const sub = submission(payer, ticketId, opts);
      const sig = await signIntent(payer, proxyAddr, sub, 1n, VALID_BEFORE);
      await v3.write.giveFeedbackWithTicketFor([sub, 1n, VALID_BEFORE, sig], { account: relayer.account });
      const f = await v3.read.readFeedback([agentId, payer.account.address, 1n]);
      assert.equal(f[0], 100n);
    });

    it("rejects an expired deadline", async function () {
      const { payer, relayer, v3, proxyAddr, ticketId, opts } = await setupWithTicket();
      const sub = submission(payer, ticketId, opts);
      const sig = await signIntent(payer, proxyAddr, sub, 1n, 1n); // deadline in the past
      await assert.rejects(v3.write.giveFeedbackWithTicketFor([sub, 1n, 1n, sig], { account: relayer.account }));
    });

    it("rejects a reused nonce", async function () {
      const { payer, relayer, v3, proxyAddr, opts, agentId, ticketId } = await setupWithTicket();
      const sub = submission(payer, ticketId, opts);
      const sig = await signIntent(payer, proxyAddr, sub, 7n, VALID_BEFORE);
      await v3.write.giveFeedbackWithTicketFor([sub, 7n, VALID_BEFORE, sig], { account: relayer.account });
      // Reusing nonce 7 (even with a fresh ticket) must revert.
      await assert.rejects(v3.write.giveFeedbackWithTicketFor([sub, 7n, VALID_BEFORE, sig], { account: relayer.account }));
    });

    it("rejects a bad signature", async function () {
      const { payer, relayer, v3, proxyAddr, ticketId, opts } = await setupWithTicket();
      const sub = submission(payer, ticketId, opts);
      // Sign over a different value than the submission carries.
      const sig = await signIntent(payer, proxyAddr, { ...sub, value: 999n }, 1n, VALID_BEFORE);
      await assert.rejects(v3.write.giveFeedbackWithTicketFor([sub, 1n, VALID_BEFORE, sig], { account: relayer.account }));
    });
  });

  // -------------------------------------------------------------------------
  describe("disputes", function () {
    async function setupWithFeedback() {
      const [owner, payer, relayer, stranger] = await viem.getWalletClients();
      const { v3, minter, identity, token } = await deployV3();
      const agentId = await getAgentIdFromRegistration(await identity.write.register(["ipfs://agent"], { account: owner.account }));
      const opts = { requestHash: fh("req"), interactionHash: fh("interaction"), payTo: "0x000000000000000000000000000000000000dEaD" as `0x${string}`, value: 1000n, nonce: fh("n1"), endpoint: "https://svc" };
      const ticketId = await mintTicketWith(minter, token, payer, relayer, agentId, opts);
      await v3.write.giveFeedbackWithTicket([ticketId, 100n, 0, "q", "t", "https://svc", "ipfs://tf", opts.interactionHash, fh("fb")], { account: payer.account });
      return { owner, payer, stranger, v3, agentId };
    }

    it("lets an authorized agent dispute, excluding it from getSummary", async function () {
      const { owner, payer, v3, agentId } = await setupWithFeedback();
      assert.equal((await v3.read.getSummary([agentId, [payer.account.address], "", ""]))[0], 1n);
      await v3.write.disputeFeedback([agentId, payer.account.address, 1n], { account: owner.account });
      assert.equal((await v3.read.readFeedback([agentId, payer.account.address, 1n]))[5], true);
      assert.equal((await v3.read.getSummary([agentId, [payer.account.address], "", ""]))[0], 0n);
    });

    it("rejects a dispute from a non-agent caller", async function () {
      const { stranger, payer, v3, agentId } = await setupWithFeedback();
      await assert.rejects(v3.write.disputeFeedback([agentId, payer.account.address, 1n], { account: stranger.account }));
    });

    it("rejects disputing a non-existent feedback index", async function () {
      const { owner, payer, v3, agentId } = await setupWithFeedback();
      await assert.rejects(v3.write.disputeFeedback([agentId, payer.account.address, 99n], { account: owner.account }));
    });

    it("rejects a double dispute", async function () {
      const { owner, payer, v3, agentId } = await setupWithFeedback();
      await v3.write.disputeFeedback([agentId, payer.account.address, 1n], { account: owner.account });
      await assert.rejects(v3.write.disputeFeedback([agentId, payer.account.address, 1n], { account: owner.account }));
    });
  });

  // ---- signing helpers shared by the EIP-3009 suite ----
  async function signTransfer(payer: any, token: any, opts: any) {
    return await payer.signTypedData({
      domain: { name: "Mock3009", version: "1", chainId, verifyingContract: token.address },
      types: { TransferWithAuthorization: [
        { name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" },
        { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
      ] },
      primaryType: "TransferWithAuthorization",
      message: { from: payer.account.address, to: opts.payTo, value: opts.value, validAfter: 0n, validBefore: VALID_BEFORE, nonce: opts.nonce },
    });
  }
  async function signMetadata(payer: any, minter: any, agentId: bigint, token: any, opts: any) {
    return await payer.signTypedData({
      domain: { name: "ERC8004TicketMinter", version: "1", chainId, verifyingContract: minter.address },
      types: { TicketMintAuthorization: [
        { name: "agentId", type: "uint256" }, { name: "requestHash", type: "bytes32" }, { name: "interactionHash", type: "bytes32" },
        { name: "endpoint", type: "string" }, { name: "token", type: "address" }, { name: "payTo", type: "address" },
        { name: "value", type: "uint256" }, { name: "nonce", type: "bytes32" },
      ] },
      primaryType: "TicketMintAuthorization",
      message: { agentId, requestHash: opts.requestHash, interactionHash: opts.interactionHash, endpoint: opts.endpoint, token: token.address, payTo: opts.payTo, value: opts.value, nonce: opts.nonce },
    });
  }
  function settlement(token: any, opts: any, sig: `0x${string}`, metaSig: `0x${string}`) {
    return { token: token.address, payTo: opts.payTo, value: opts.value, validAfter: 0n, validBefore: VALID_BEFORE, nonce: opts.nonce, signature: sig, metadataSignature: metaSig };
  }
  async function mintTicketWith(minter: any, token: any, payer: any, relayer: any, agentId: bigint, opts: any) {
    await token.write.mint([payer.account.address, opts.value]);
    const sig = await signTransfer(payer, token, opts);
    const metaSig = await signMetadata(payer, minter, agentId, token, opts);
    const ticketId = await minter.read.nextTicketId();
    await minter.write.settleAndMintTicketEIP3009(
      [payer.account.address, agentId, opts.requestHash, opts.interactionHash, opts.endpoint, settlement(token, opts, sig, metaSig)],
      { account: relayer.account });
    return ticketId as bigint;
  }
});
