#!/usr/bin/env node
/**
 * azure-pqc-inventory — command-line entrypoint.
 *
 * Scans Azure Key Vault, App Service, and Front Door for quantum-vulnerable
 * cryptography and prints a post-quantum readiness inventory.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import type { RiskLevel, ScannerResult } from "./types.js";
import { scanKeyVault } from "./scanners/keyvault.js";
import { scanAppService } from "./scanners/appservice.js";
import { scanFrontDoor } from "./scanners/frontdoor.js";
import { buildReport, meetsThreshold, renderText } from "./report.js";
import { color, setColorEnabled } from "./color.js";

interface CliOptions {
  subscriptionId?: string;
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
  vaultNames: string[];
  resourceGroups: string[];
  scanners: Set<"keyvault" | "appservice" | "frontdoor">;
  json: boolean;
  output?: string;
  failOn?: RiskLevel;
  color: boolean;
  tlsTimeoutMs: number;
  keyAgeWarnDays: number;
}

const VALID_LEVELS: RiskLevel[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];

function version(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8"));
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

function printHelp(): void {
  process.stdout.write(`azure-pqc-inventory — Azure post-quantum cryptography inventory scanner

USAGE
  azure-pqc-inventory [options]

SCAN SELECTION (default: all three)
  --keyvault                 Scan Key Vault keys + certificates
  --appservice               Scan App Service / Function App TLS posture
  --frontdoor                Scan Front Door custom-domain TLS posture

SCOPE & AUTH
  --subscription <id>        Azure subscription id   (env AZURE_SUBSCRIPTION_ID)
  --tenant <id>              Service-principal tenant (env AZURE_TENANT_ID)
  --client-id <id>           Service-principal app id (env AZURE_CLIENT_ID)
  --client-secret <secret>   Service-principal secret (env AZURE_CLIENT_SECRET)
  --vault <name>             Limit Key Vault scan to this vault (repeatable)
  --resource-group <name>    Limit App Service / Front Door to this RG (repeatable)
  --tls-timeout <ms>         Per-host TLS probe timeout (default 5000)
  --key-age-days <days>      Flag keys older than this (default 365)

  When the service-principal flags/vars are omitted, DefaultAzureCredential is
  used (environment, Managed Identity, Azure CLI 'az login', …).

OUTPUT
  --json                     Emit the report as JSON
  --output <file>            Write the report to a file instead of stdout
  --fail-on <level>          Exit 2 if any finding is at or above this severity
                             (CRITICAL | HIGH | MEDIUM | LOW)
  --no-color                 Disable ANSI colour
  -h, --help                 Show this help
  -v, --version              Show version

EXIT CODES
  0  success, no threshold breached
  1  error (bad arguments, authentication, or scan failure)
  2  --fail-on threshold met

EXAMPLES
  # Scan everything in a subscription using your 'az login' session
  azure-pqc-inventory --subscription 00000000-0000-0000-0000-000000000000

  # Only Key Vault, JSON to a file, with a service principal
  AZURE_TENANT_ID=… AZURE_CLIENT_ID=… AZURE_CLIENT_SECRET=… \\
    azure-pqc-inventory --keyvault --json --output inventory.json

  # CI gate: fail the build if any HIGH+ finding exists
  azure-pqc-inventory --subscription <id> --fail-on HIGH
`);
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    subscriptionId: process.env.AZURE_SUBSCRIPTION_ID,
    tenantId: process.env.AZURE_TENANT_ID,
    clientId: process.env.AZURE_CLIENT_ID,
    clientSecret: process.env.AZURE_CLIENT_SECRET,
    vaultNames: [],
    resourceGroups: [],
    scanners: new Set(),
    json: false,
    color: true,
    tlsTimeoutMs: 5000,
    keyAgeWarnDays: 365,
  };

  const need = (name: string, value: string | undefined): string => {
    if (value === undefined) {
      fail(`option ${name} requires a value`);
    }
    return value as string;
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "-h":
      case "--help":
        printHelp();
        process.exit(0);
        break;
      case "-v":
      case "--version":
        process.stdout.write(version() + "\n");
        process.exit(0);
        break;
      case "--keyvault":
        opts.scanners.add("keyvault");
        break;
      case "--appservice":
        opts.scanners.add("appservice");
        break;
      case "--frontdoor":
        opts.scanners.add("frontdoor");
        break;
      case "--subscription":
        opts.subscriptionId = need(arg, argv[++i]);
        break;
      case "--tenant":
        opts.tenantId = need(arg, argv[++i]);
        break;
      case "--client-id":
        opts.clientId = need(arg, argv[++i]);
        break;
      case "--client-secret":
        opts.clientSecret = need(arg, argv[++i]);
        break;
      case "--vault":
        opts.vaultNames.push(need(arg, argv[++i]));
        break;
      case "--resource-group":
        opts.resourceGroups.push(need(arg, argv[++i]));
        break;
      case "--tls-timeout":
        opts.tlsTimeoutMs = positiveInt(arg, need(arg, argv[++i]));
        break;
      case "--key-age-days":
        opts.keyAgeWarnDays = positiveInt(arg, need(arg, argv[++i]));
        break;
      case "--json":
        opts.json = true;
        break;
      case "--output":
        opts.output = need(arg, argv[++i]);
        break;
      case "--fail-on": {
        const level = need(arg, argv[++i]).toUpperCase() as RiskLevel;
        if (!VALID_LEVELS.includes(level)) {
          fail(`--fail-on must be one of ${VALID_LEVELS.join(", ")}`);
        }
        opts.failOn = level;
        break;
      }
      case "--no-color":
        opts.color = false;
        break;
      default:
        fail(`unknown option: ${arg}`);
    }
  }

  // Default: run every scanner.
  if (opts.scanners.size === 0) {
    opts.scanners.add("keyvault");
    opts.scanners.add("appservice");
    opts.scanners.add("frontdoor");
  }
  return opts;
}

function fail(message: string): never {
  process.stderr.write(`error: ${message}\n`);
  process.exit(1);
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  if (!opts.color || opts.json) setColorEnabled(false);

  if (!opts.subscriptionId) {
    fail(
      "no subscription id (pass --subscription or set AZURE_SUBSCRIPTION_ID). Run with --help for usage.",
    );
  }

  const auth = {
    subscriptionId: opts.subscriptionId,
    tenantId: opts.tenantId,
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
  };

  const results: ScannerResult[] = [];
  try {
    if (opts.scanners.has("keyvault")) {
      process.stderr.write(color.dim("Scanning Key Vault…\n"));
      results.push(await scanKeyVault({
        ...auth,
        vaultNames: nonEmpty(opts.vaultNames),
        keyAgeWarnDays: opts.keyAgeWarnDays,
      }));
    }
    if (opts.scanners.has("appservice")) {
      process.stderr.write(color.dim("Scanning App Service…\n"));
      results.push(
        await scanAppService({
          ...auth,
          resourceGroups: nonEmpty(opts.resourceGroups),
          tlsTimeoutMs: opts.tlsTimeoutMs,
        }),
      );
    }
    if (opts.scanners.has("frontdoor")) {
      process.stderr.write(color.dim("Scanning Front Door…\n"));
      results.push(
        await scanFrontDoor({
          ...auth,
          resourceGroups: nonEmpty(opts.resourceGroups),
          tlsTimeoutMs: opts.tlsTimeoutMs,
        }),
      );
    }
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }

  const report = buildReport(opts.subscriptionId, results);
  const rendered = opts.json ? JSON.stringify(report, null, 2) : renderText(report);

  if (opts.output) {
    writeFileSync(opts.output, rendered + "\n");
    process.stderr.write(color.dim(`Report written to ${opts.output}\n`));
  } else {
    process.stdout.write(rendered + "\n");
  }

  if (opts.failOn && meetsThreshold(report, opts.failOn)) {
    process.stderr.write(
      color.red(`Threshold ${opts.failOn} met — exiting 2.\n`),
    );
    process.exit(2);
  }
}

function nonEmpty(arr: string[]): string[] | undefined {
  return arr.length ? arr : undefined;
}

function positiveInt(option: string, raw: string): number {
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    fail(`${option} requires a positive integer`);
  }
  return value;
}

main().catch((err) => {
  process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
