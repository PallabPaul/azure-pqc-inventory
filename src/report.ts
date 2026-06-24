/**
 * Reporting: aggregate scanner results, compute a quantum-risk score, and
 * render either a human-readable table or a machine-readable JSON document.
 */

import type { CryptoResource, RiskLevel, ScannerResult } from "./types.js";
import { color } from "./color.js";

const SEVERITY_WEIGHT: Record<RiskLevel, number> = {
  CRITICAL: 40,
  HIGH: 20,
  MEDIUM: 8,
  LOW: 2,
  NONE: 0,
};

const SEVERITY_ORDER: RiskLevel[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];

export interface InventoryReport {
  generatedAt: string;
  subscriptionId: string;
  riskScore: number;
  riskLevel: RiskLevel;
  totals: {
    resources: number;
    quantumVulnerable: number;
    quantumReady: number;
    bySeverity: Record<RiskLevel, number>;
  };
  scanners: {
    name: string;
    scanned: string[];
    errors: { target: string; message: string }[];
  }[];
  resources: CryptoResource[];
}

/** Combine per-scanner results into a single scored report. */
export function buildReport(
  subscriptionId: string,
  results: ScannerResult[],
): InventoryReport {
  const resources = results.flatMap((r) => r.resources);

  const bySeverity: Record<RiskLevel, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    NONE: 0,
  };
  let weightSum = 0;
  let quantumVulnerable = 0;
  let quantumReady = 0;
  for (const res of resources) {
    bySeverity[res.risk] += 1;
    weightSum += SEVERITY_WEIGHT[res.risk];
    if (res.pqReady) quantumReady += 1;
    else if (res.risk === "HIGH" || res.risk === "CRITICAL" || res.risk === "MEDIUM") {
      quantumVulnerable += 1;
    }
  }

  const riskScore = Math.min(100, weightSum);
  return {
    generatedAt: new Date().toISOString(),
    subscriptionId,
    riskScore,
    riskLevel: scoreToLevel(riskScore),
    totals: {
      resources: resources.length,
      quantumVulnerable,
      quantumReady,
      bySeverity,
    },
    scanners: results.map((r) => ({
      name: r.scanner,
      scanned: r.scanned,
      errors: r.errors,
    })),
    resources,
  };
}

/** Map a 0–100 score to an overall level. */
export function scoreToLevel(score: number): RiskLevel {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 40) return "MEDIUM";
  if (score >= 20) return "LOW";
  return "NONE";
}

/** True when any finding meets or exceeds the given threshold severity. */
export function meetsThreshold(report: InventoryReport, threshold: RiskLevel): boolean {
  const idx = SEVERITY_ORDER.indexOf(threshold);
  for (let i = 0; i <= idx; i++) {
    if (report.totals.bySeverity[SEVERITY_ORDER[i]] > 0) return true;
  }
  return false;
}

const SEVERITY_COLOR: Record<RiskLevel, (s: string) => string> = {
  CRITICAL: (s) => color.red(color.bold(s)),
  HIGH: (s) => color.red(s),
  MEDIUM: (s) => color.yellow(s),
  LOW: (s) => color.blue(s),
  NONE: (s) => color.green(s),
};

/** Render a human-readable report to a string. */
export function renderText(report: InventoryReport): string {
  const lines: string[] = [];
  const sev = report.riskLevel;

  lines.push("");
  lines.push(color.bold("Azure Post-Quantum Cryptography Inventory"));
  lines.push(color.dim(`Subscription ${report.subscriptionId}`));
  lines.push(color.dim(`Generated ${report.generatedAt}`));
  lines.push("");

  // Per-scanner summary.
  for (const s of report.scanners) {
    const scannedCount = s.scanned.length;
    const errCount = s.errors.length;
    lines.push(
      `${color.bold(scannerLabel(s.name))}  ` +
        color.dim(`${scannedCount} scanned, ${errCount} error(s)`),
    );
    for (const e of s.errors) {
      lines.push(color.dim(`    ! ${e.target}: ${e.message}`));
    }
  }
  lines.push("");

  // Findings grouped by severity (most severe first).
  const grouped = groupBySeverity(report.resources);
  for (const level of SEVERITY_ORDER) {
    const items = grouped[level];
    if (!items.length) continue;
    lines.push(SEVERITY_COLOR[level](`${level} (${items.length})`));
    for (const r of items) {
      lines.push(`  ${badge(r.risk)} ${color.bold(r.name)}  ${color.dim(`[${r.type} · ${r.region}]`)}`);
      lines.push(`      ${color.dim("algorithm:")} ${r.algorithm}`);
      lines.push(`      ${r.details}`);
    }
    lines.push("");
  }

  // Summary footer.
  const t = report.totals;
  lines.push(color.bold("Summary"));
  lines.push(
    `  Resources: ${t.resources}   ` +
      `Quantum-vulnerable: ${color.red(String(t.quantumVulnerable))}   ` +
      `Quantum-ready: ${color.green(String(t.quantumReady))}`,
  );
  lines.push(
    `  Severity:  ` +
      `${SEVERITY_COLOR.CRITICAL("CRIT " + t.bySeverity.CRITICAL)}  ` +
      `${SEVERITY_COLOR.HIGH("HIGH " + t.bySeverity.HIGH)}  ` +
      `${SEVERITY_COLOR.MEDIUM("MED " + t.bySeverity.MEDIUM)}  ` +
      `${SEVERITY_COLOR.LOW("LOW " + t.bySeverity.LOW)}  ` +
      `${SEVERITY_COLOR.NONE("OK " + t.bySeverity.NONE)}`,
  );
  lines.push(
    `  Quantum risk score: ${SEVERITY_COLOR[sev](String(report.riskScore))}/100  (${sev})`,
  );
  lines.push("");
  return lines.join("\n");
}

function groupBySeverity(resources: CryptoResource[]): Record<RiskLevel, CryptoResource[]> {
  const out: Record<RiskLevel, CryptoResource[]> = {
    CRITICAL: [],
    HIGH: [],
    MEDIUM: [],
    LOW: [],
    NONE: [],
  };
  for (const r of resources) out[r.risk].push(r);
  return out;
}

function badge(level: RiskLevel): string {
  return SEVERITY_COLOR[level](`[${level}]`);
}

function scannerLabel(name: string): string {
  switch (name) {
    case "keyvault":
      return "Key Vault";
    case "appservice":
      return "App Service";
    case "frontdoor":
      return "Front Door";
    default:
      return name;
  }
}
