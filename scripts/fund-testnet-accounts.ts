import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Keypair } from "@stellar/stellar-sdk";

const DEFAULT_ROLES = [
  "ADMIN",
  "BRAND_A",
  "BRAND_B",
  "SERVICE_CENTER",
  "CONSUMER_1",
  "CONSUMER_2",
];

const FRIENDBOT_URL = "https://friendbot.stellar.org";
const HORIZON_TESTNET_URL = process.env.HORIZON_URL ?? "https://horizon-testnet.stellar.org";
const DEFAULT_OUTPUT_FILE = ".env.test";

interface CliOptions {
  roles: string[];
  deterministic: boolean;
  seedPrefix: string;
  outFile: string;
  maxRetries: number;
}

interface FundedAccount {
  role: string;
  publicKey: string;
  secretKey: string;
  xlmBalance: string;
}

function normalizeRole(role: string): string {
  return role
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function parseArgs(argv: string[]): CliOptions {
  let count: number | null = null;
  let rolesArg: string | null = null;
  let deterministic = false;
  let seedPrefix = "veritag-testnet-seed";
  let outFile = DEFAULT_OUTPUT_FILE;
  let maxRetries = 5;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--count" && argv[i + 1]) {
      count = Number.parseInt(argv[++i]!, 10);
    } else if (arg === "--roles" && argv[i + 1]) {
      rolesArg = argv[++i]!;
    } else if (arg === "--deterministic") {
      deterministic = true;
    } else if (arg === "--seed" && argv[i + 1]) {
      deterministic = true;
      seedPrefix = argv[++i]!;
    } else if (arg === "--out" && argv[i + 1]) {
      outFile = argv[++i]!;
    } else if (arg === "--retries" && argv[i + 1]) {
      maxRetries = Number.parseInt(argv[++i]!, 10);
    } else if (arg === "--help" || arg === "-h") {
      console.log(`Usage: tsx scripts/fund-testnet-accounts.ts [options]

Options:
  --count <n>          Number of generic accounts to generate (ACCOUNT_1..ACCOUNT_N)
  --roles <a,b,c>      Comma-separated list of role names
                       (default: ${DEFAULT_ROLES.join(",")})
  --deterministic      Derive deterministic keypairs from --seed
  --seed <string>      Seed prefix for deterministic derivation (implies --deterministic)
  --out <path>         Output .env file path (default: ${DEFAULT_OUTPUT_FILE})
  --retries <n>        Max Friendbot retry attempts per account (default: 5)
`);
      process.exit(0);
    }
  }

  let roles = DEFAULT_ROLES;
  if (rolesArg) {
    roles = rolesArg
      .split(",")
      .map(normalizeRole)
      .filter((r) => r.length > 0);
  } else if (count !== null) {
    if (!Number.isFinite(count) || count < 1) {
      throw new Error(`Invalid --count value: ${count}`);
    }
    roles = Array.from({ length: count }, (_, idx) => `ACCOUNT_${idx + 1}`);
  }

  if (roles.length === 0) {
    throw new Error("At least one account role must be specified.");
  }

  return { roles, deterministic, seedPrefix, outFile, maxRetries };
}

function createKeypairForRole(role: string, deterministic: boolean, seedPrefix: string): Keypair {
  if (!deterministic) {
    return Keypair.random();
  }
  const seed = createHash("sha256").update(`${seedPrefix}:${role}`).digest();
  return Keypair.fromRawEd25519Seed(seed);
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

async function fundViaFriendbot(publicKey: string, maxRetries: number): Promise<void> {
  const url = `${FRIENDBOT_URL}?addr=${encodeURIComponent(publicKey)}`;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }

      const body = await response.text();
      // Horizon/Friendbot returns 400 if account is already funded
      if (response.status === 400 && body.toLowerCase().includes("createaccountalreadyexist")) {
        return;
      }

      const retryable = response.status === 429 || response.status >= 500;
      if (!retryable || attempt === maxRetries) {
        throw new Error(`Friendbot HTTP ${response.status}: ${body}`);
      }
    } catch (err) {
      if (attempt === maxRetries) {
        throw err;
      }
    }

    const backoffMs = Math.min(1000 * 2 ** (attempt - 1), 16_000);
    console.warn(
      `  Friendbot attempt ${attempt}/${maxRetries} failed for ${publicKey}; retrying in ${backoffMs}ms...`,
    );
    await sleep(backoffMs);
  }
}

async function verifyTestnetBalance(publicKey: string): Promise<string> {
  const url = `${HORIZON_TESTNET_URL.replace(/\/$/, "")}/accounts/${encodeURIComponent(publicKey)}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Horizon lookup failed for ${publicKey}: HTTP ${response.status}`);
  }

  const data = (await response.json()) as {
    balances?: Array<{ asset_type: string; balance: string }>;
  };
  const nativeBalance = data.balances?.find((b) => b.asset_type === "native")?.balance ?? "0";
  if (Number.parseFloat(nativeBalance) <= 0) {
    throw new Error(`Account ${publicKey} has non-positive XLM balance: ${nativeBalance}`);
  }
  return nativeBalance;
}

function formatEnvFile(accounts: FundedAccount[], deterministic: boolean): string {
  const lines: string[] = [
    "# Generated by scripts/fund-testnet-accounts.ts",
    `# Generated at: ${new Date().toISOString()}`,
    `# Mode: ${deterministic ? "deterministic" : "random"}`,
    `STELLAR_NETWORK=testnet`,
    `HORIZON_URL=${HORIZON_TESTNET_URL}`,
    "",
  ];

  for (const account of accounts) {
    lines.push(`# ${account.role} (Testnet XLM: ${account.xlmBalance})`);
    lines.push(`TESTNET_${account.role}_PUBLIC_KEY=${account.publicKey}`);
    lines.push(`TESTNET_${account.role}_SECRET_KEY=${account.secretKey}`);
    lines.push("");
  }

  return lines.join("\n");
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const funded: FundedAccount[] = [];

  console.log(
    `Funding ${options.roles.length} Stellar testnet account(s) [${options.deterministic ? "deterministic" : "random"}]...`,
  );

  for (const role of options.roles) {
    const keypair = createKeypairForRole(role, options.deterministic, options.seedPrefix);
    const publicKey = keypair.publicKey();
    const secretKey = keypair.secret();

    console.log(`- ${role}: ${publicKey}`);
    await fundViaFriendbot(publicKey, options.maxRetries);
    const xlmBalance = await verifyTestnetBalance(publicKey);
    console.log(`  Funded & verified (${xlmBalance} XLM)`);

    funded.push({ role, publicKey, secretKey, xlmBalance });
  }

  const envContent = formatEnvFile(funded, options.deterministic);
  const outPath = resolve(process.cwd(), options.outFile);
  await writeFile(outPath, envContent, { encoding: "utf8", mode: 0o600 });

  console.log("");
  console.log(`Wrote ${funded.length} funded account(s) to ${options.outFile}`);
  console.log("--- .env preview ---");
  console.log(envContent.trimEnd());
}

main().catch((err: unknown) => {
  console.error("Failed to fund testnet accounts:", err);
  process.exit(1);
});
