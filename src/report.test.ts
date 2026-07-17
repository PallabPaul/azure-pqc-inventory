import test from "node:test";
import assert from "node:assert/strict";

import { buildReport, meetsThreshold, scoreToLevel } from "./report.js";
import type { ScannerResult } from "./types.js";

test("report aggregation and CI thresholds are deterministic", () => {
  const result: ScannerResult = {
    scanner: "keyvault",
    scanned: ["vault-a"],
    errors: [],
    resources: [
      {
        id: "rsa",
        name: "rsa",
        type: "Key Vault Key",
        region: "eastus",
        algorithm: "RSA-4096",
        risk: "HIGH",
        pqReady: false,
        details: "classical",
      },
      {
        id: "aes",
        name: "aes",
        type: "Key Vault Key",
        region: "eastus",
        algorithm: "AES-256",
        risk: "LOW",
        pqReady: true,
        details: "symmetric",
      },
    ],
  };
  const report = buildReport("sub", [result]);
  assert.equal(report.riskScore, 22);
  assert.equal(report.riskLevel, "LOW");
  assert.equal(report.totals.quantumVulnerable, 1);
  assert.equal(report.totals.quantumReady, 1);
  assert.equal(meetsThreshold(report, "HIGH"), true);
  assert.equal(meetsThreshold(report, "CRITICAL"), false);
  assert.equal(scoreToLevel(80), "CRITICAL");
});