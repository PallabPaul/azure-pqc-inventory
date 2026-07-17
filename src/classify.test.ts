import test from "node:test";
import assert from "node:assert/strict";

import {
  classifyRisk,
  describeCertAlgorithm,
  describeKeyAlgorithm,
  isPqReady,
} from "./classify.js";

test("all RSA and EC public-key material remains Shor-vulnerable", () => {
  for (const algorithm of ["RSA-2048", "RSA-4096", "RSA-HSM-4096", "EC-P256", "EC-HSM-P521"]) {
    assert.equal(classifyRisk(algorithm), "HIGH", algorithm);
    assert.equal(isPqReady(algorithm), false, algorithm);
  }
});

test("AES-256 is quantum-ready while AES-128 is not", () => {
  assert.equal(classifyRisk("AES-256"), "LOW");
  assert.equal(isPqReady("AES-256"), true);
  assert.equal(classifyRisk("AES-128"), "MEDIUM");
  assert.equal(isPqReady("AES-128"), false);
});

test("Azure key metadata is canonicalized", () => {
  assert.equal(describeKeyAlgorithm({ kty: "RSA-HSM", keySize: 3072 }), "RSA-HSM-3072");
  assert.equal(describeCertAlgorithm("EC", undefined, "P-384"), "EC-P384");
});