import { execSync } from "child_process";
import hre from "hardhat";
import {
  encodeAbiParameters,
  encodeFunctionData,
  Hex,
  keccak256,
  serializeTransaction,
  getCreate2Address,
} from "viem";
import { privateKeyToAccount, toAccount } from "viem/accounts";
import dotenv from "dotenv";
import {
  SAFE_SINGLETON_FACTORY,
  PERMIT2_ADDRESS,
  IMPLEMENTATION_SALTS,
  TICKET_MINTER_SALT,
  MAINNET_ADDRESSES,
  EXPECTED_OWNER,
} from "./addresses";

dotenv.config();

/**
 * Step 4 — Ethereum Mainnet ONLY: upgrade ReputationRegistry to v3 (ticket-gated).
 *
 * Performs, idempotently:
 *   1. Deploy the v3 ReputationRegistryUpgradeable implementation via CREATE2.
 *   2. Deploy the paired TicketMinter via CREATE2 (bound to the existing proxy).
 *   3. Owner upgrades the proxy: upgradeToAndCall(v3Impl, initializeV3(identity, minter)).
 *
 * Safety:
 *   - Refuses to run on any chain other than Ethereum Mainnet (chainId 1).
 *   - DRY RUN by default. Set EXECUTE=true to broadcast.
 *   - Deploys are deterministic (CREATE2) and skipped if code already exists.
 *   - The x402 facilitator allowlist is NOT set here — see the printed follow-up step.
 *
 * Signing: prefers HSM (slot 1), falls back to OWNER_PRIVATE_KEY in .env.
 *
 * Run:  npx hardhat run scripts/upgrade-reputation-v3-mainnet.ts --network mainnet
 */

const ETHEREUM_MAINNET = 1;
const EXECUTE = process.env.EXECUTE === "true";

async function main() {
  const { viem } = await hre.network.connect();
  const publicClient = await viem.getPublicClient();

  const chainId = await publicClient.getChainId();
  if (chainId !== ETHEREUM_MAINNET) {
    throw new Error(
      `This script is scoped to Ethereum Mainnet (chainId 1) only. Connected chainId: ${chainId}.`
    );
  }

  console.log("ReputationRegistry v3 upgrade — Ethereum Mainnet");
  console.log("================================================");
  console.log("Mode:", EXECUTE ? "EXECUTE (will broadcast)" : "DRY RUN (no broadcast; set EXECUTE=true to send)");
  console.log("");

  // --- Resolve owner/deployer signer only when broadcasting (DRY RUN needs no keys) ---
  let ownerWallet: any = undefined;
  if (EXECUTE) {
    const ownerAccount = resolveOwnerAccount();
    console.log("Signer address:        ", ownerAccount.address);
    console.log("Expected owner:        ", EXPECTED_OWNER);
    if (ownerAccount.address.toLowerCase() !== EXPECTED_OWNER.toLowerCase()) {
      console.log("⚠️  Signer is NOT the expected owner — the upgrade tx (onlyOwner) would revert.");
    }
    ownerWallet = await viem.getWalletClient(ownerAccount.address as Hex, { account: ownerAccount as any });
  } else {
    console.log("Signer:                 (none — DRY RUN). Owner for execution:", EXPECTED_OWNER);
  }
  console.log("");

  const reputationProxy = MAINNET_ADDRESSES.reputationRegistry as Hex;
  const identityProxy = MAINNET_ADDRESSES.identityRegistry as Hex;

  // --- 1. Compute & deploy v3 implementation via CREATE2 ---
  const v3Artifact = await hre.artifacts.readArtifact("ReputationRegistryUpgradeable");
  const v3Bytecode = v3Artifact.bytecode as Hex;
  const v3ImplAddress = getCreate2Address({
    from: SAFE_SINGLETON_FACTORY,
    salt: IMPLEMENTATION_SALTS.reputationRegistry,
    bytecodeHash: keccak256(v3Bytecode),
  });
  const v3DeployData = (IMPLEMENTATION_SALTS.reputationRegistry + v3Bytecode.slice(2)) as Hex;

  console.log("1. v3 ReputationRegistry implementation");
  console.log("   CREATE2 address:    ", v3ImplAddress);
  await deployIfAbsent("v3 implementation", v3ImplAddress, SAFE_SINGLETON_FACTORY, v3DeployData, publicClient, ownerWallet);
  console.log("");

  // --- 2. Compute & deploy TicketMinter via CREATE2 ---
  // constructor(address owner_, address permit2_, address reputationRegistry_, address identityRegistry_)
  const minterArtifact = await hre.artifacts.readArtifact("TicketMinter");
  const minterCtorArgs = encodeAbiParameters(
    [{ type: "address" }, { type: "address" }, { type: "address" }, { type: "address" }],
    [EXPECTED_OWNER as Hex, PERMIT2_ADDRESS as Hex, reputationProxy, identityProxy]
  );
  const minterInitcode = ((minterArtifact.bytecode as Hex) + minterCtorArgs.slice(2)) as Hex;
  const minterAddress = getCreate2Address({
    from: SAFE_SINGLETON_FACTORY,
    salt: TICKET_MINTER_SALT,
    bytecodeHash: keccak256(minterInitcode),
  });
  const minterDeployData = (TICKET_MINTER_SALT + minterInitcode.slice(2)) as Hex;

  console.log("2. TicketMinter (owner, permit2, reputationRegistry, identityRegistry)");
  console.log("   owner:              ", EXPECTED_OWNER);
  console.log("   permit2:            ", PERMIT2_ADDRESS);
  console.log("   reputationRegistry: ", reputationProxy);
  console.log("   identityRegistry:   ", identityProxy);
  console.log("   CREATE2 address:    ", minterAddress);
  await deployIfAbsent("TicketMinter", minterAddress, SAFE_SINGLETON_FACTORY, minterDeployData, publicClient, ownerWallet);
  console.log("");

  // --- 3. Upgrade the proxy: upgradeToAndCall(v3Impl, initializeV3(identity, minter)) ---
  const initV3Data = encodeFunctionData({
    abi: v3Artifact.abi,
    functionName: "initializeV3",
    args: [identityProxy, minterAddress],
  });
  const upgradeData = encodeFunctionData({
    abi: v3Artifact.abi, // upgradeToAndCall is inherited (UUPS) and present in the ABI
    functionName: "upgradeToAndCall",
    args: [v3ImplAddress, initV3Data],
  });

  console.log("3. Upgrade ReputationRegistry proxy");
  console.log("   proxy:              ", reputationProxy);
  console.log("   -> implementation:  ", v3ImplAddress);
  console.log("   initializeV3 args:  ", { identityRegistry: identityProxy, ticketMinter: minterAddress });

  const currentImpl = await getImplementation(reputationProxy, publicClient);
  if (currentImpl?.toLowerCase() === v3ImplAddress.toLowerCase()) {
    console.log("   ⏭️  Proxy already points at the v3 implementation.");
  } else if (!EXECUTE) {
    console.log("   [DRY RUN] upgradeToAndCall calldata (send from owner to the proxy):");
    console.log("   to:  ", reputationProxy);
    console.log("   data:", upgradeData);
  } else {
    const txHash = await ownerWallet.sendTransaction({ to: reputationProxy, data: upgradeData });
    await publicClient.waitForTransactionReceipt({ hash: txHash });
    console.log("   ✅ Upgraded. tx:", txHash);
  }
  console.log("");

  // --- Verify (read-only) ---
  const v3 = await viem.getContractAt("ReputationRegistryUpgradeable", reputationProxy);
  if (EXECUTE) {
    console.log("Verification:");
    console.log("   getVersion():       ", await v3.read.getVersion());
    console.log("   getIdentityRegistry:", await v3.read.getIdentityRegistry());
    console.log("   getTicketMinter():  ", await v3.read.getTicketMinter());
    console.log("");
  }

  console.log("Follow-up (manual, owner-only): allowlist the x402 facilitator(s):");
  console.log(`   TicketMinter(${minterAddress}).setFacilitator(<facilitatorAddress>, true)`);
  console.log("");
  console.log(EXECUTE ? "✅ Done." : "DRY RUN complete. Re-run with EXECUTE=true to broadcast.");
}

async function deployIfAbsent(
  label: string,
  expectedAddress: Hex,
  factory: string,
  deployData: Hex,
  publicClient: any,
  wallet: any,
) {
  const code = await publicClient.getBytecode({ address: expectedAddress });
  if (code && code !== "0x") {
    console.log(`   ⏭️  ${label} already deployed.`);
    return;
  }
  if (!EXECUTE) {
    console.log(`   [DRY RUN] would deploy ${label} via CREATE2 factory.`);
    console.log("   to:  ", factory);
    console.log("   data:", deployData.slice(0, 74) + "… (" + ((deployData.length - 2) / 2) + " bytes)");
    return;
  }
  const txHash = await wallet.sendTransaction({ to: factory as Hex, data: deployData });
  await publicClient.waitForTransactionReceipt({ hash: txHash });
  console.log(`   ✅ Deployed ${label}. tx:`, txHash);
}

async function getImplementation(proxyAddress: Hex, publicClient: any): Promise<string | null> {
  // ERC-1967 implementation slot
  const implSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
  const raw = await publicClient.getStorageAt({ address: proxyAddress, slot: implSlot as Hex });
  return raw ? `0x${raw.slice(-40)}` : null;
}

function resolveOwnerAccount() {
  const ownerPrivateKey = process.env.OWNER_PRIVATE_KEY;
  if (ownerPrivateKey) {
    console.log("WARNING: Using OWNER_PRIVATE_KEY from .env — prefer HSM in production.");
    let pk = ownerPrivateKey.startsWith("0x") ? ownerPrivateKey : `0x${ownerPrivateKey}`;
    if (pk.length !== 66 || !/^0x[0-9a-fA-F]{64}$/.test(pk)) {
      throw new Error(`Invalid OWNER_PRIVATE_KEY format.`);
    }
    return privateKeyToAccount(pk as Hex);
  }

  console.log("INFO: Signing using HSM (slot 1)");
  function hsm(cmd: string): string {
    for (let i = 0; i < 3; i++) {
      try {
        return execSync(`hsm ${cmd}`, { timeout: 5000 }).toString().trim();
      } catch {
        if (i === 2) throw new Error(`hsm ${cmd} failed after 3 retries`);
        execSync("sleep 1");
      }
    }
    throw new Error("unreachable");
  }
  const info = JSON.parse(hsm("addr"));
  const hsmAddress = info.address as Hex;
  return toAccount({
    address: hsmAddress,
    async signMessage({ message }) {
      const msg = typeof message === "string" ? new TextEncoder().encode(message) : message;
      const hash = keccak256(msg as Hex);
      const raw = hash.startsWith("0x") ? hash.slice(2) : hash;
      const result = JSON.parse(hsm(`sign ${raw}`));
      return `${result.r}${(result.s as string).slice(2)}${(result.v - 27).toString(16).padStart(2, "0")}` as Hex;
    },
    async signTransaction(tx, { serializer = serializeTransaction } = {}) {
      const serialized = serializer(tx);
      const hash = keccak256(serialized);
      const raw = hash.startsWith("0x") ? hash.slice(2) : hash;
      const result = JSON.parse(hsm(`sign ${raw}`));
      return serializer(tx, { r: result.r, s: result.s, v: BigInt(result.v) });
    },
    async signTypedData() {
      throw new Error("signTypedData not implemented");
    },
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
