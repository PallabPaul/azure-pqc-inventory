/**
 * Algorithm classification and quantum-risk scoring.
 *
 * The threat model is Shor's algorithm: a cryptographically-relevant quantum
 * computer breaks the integer-factorisation (RSA) and discrete-log (elliptic
 * curve) problems, so all RSA and EC public-key material is quantum-vulnerable.
 * Symmetric primitives (AES) are only weakened by Grover's algorithm, which
 * halves the effective key length — so AES-256 keeps a 128-bit security margin
 * and is considered quantum-resistant.
 */

import type { RiskLevel } from "./types.js";

/**
 * Build a canonical algorithm string from an Azure key's `kty` plus optional
 * key size / curve. Azure exposes `kty` like "RSA", "RSA-HSM", "EC", "EC-HSM",
 * "oct", "oct-HSM".
 *
 * Examples emitted:
 *   RSA-2048, RSA-4096, RSA-HSM-3072
 *   EC-P256, EC-P384, EC-HSM-P521
 *   AES-256 (oct), oct-HSM-256
 */
export function describeKeyAlgorithm(material: {
  kty?: string;
  keySize?: number;
  curveName?: string;
}): string {
  const kty = (material.kty ?? "").toUpperCase();
  const keySize = material.keySize;
  const curveName = material.curveName;

  if (kty.startsWith("RSA")) {
    const size = keySize ?? 2048;
    return kty.includes("HSM") ? `RSA-HSM-${size}` : `RSA-${size}`;
  }
  if (kty.startsWith("EC")) {
    const curve = (curveName ?? "P-256").replace(/^P-/, "P");
    return kty.includes("HSM") ? `EC-HSM-${curve}` : `EC-${curve}`;
  }
  if (kty.startsWith("OCT")) {
    const size = keySize ?? 256;
    return kty.includes("HSM") ? `oct-HSM-${size}` : `AES-${size}`;
  }
  return kty || "UNKNOWN";
}

/**
 * Canonical algorithm string for a certificate policy's key type / size / curve.
 */
export function describeCertAlgorithm(
  keyType?: string | null,
  keySize?: number | null,
  curve?: string | null,
): string {
  const kty = (keyType ?? "").toUpperCase();
  if (kty.startsWith("RSA")) {
    const size = keySize ?? 2048;
    return kty.includes("HSM") ? `RSA-HSM-${size}` : `RSA-${size}`;
  }
  if (kty.startsWith("EC")) {
    const c = (curve ?? "P-256").replace(/^P-/, "P");
    return kty.includes("HSM") ? `EC-HSM-${c}` : `EC-${c}`;
  }
  if (kty.startsWith("OCT")) {
    const size = keySize ?? 256;
    return kty.includes("HSM") ? `oct-HSM-${size}` : `AES-${size}`;
  }
  return kty || "UNKNOWN";
}

/**
 * Map an algorithm string to a quantum-risk level.
 *   - RSA (every key size) / EC (every curve): HIGH — broken by Shor.
 *   - AES / symmetric >=256-bit: LOW — quantum-resistant under Grover.
 *   - AES / symmetric <256-bit: MEDIUM.
 */
export function classifyRisk(algorithm: string): RiskLevel {
  if (algorithm.startsWith("RSA")) {
    return "HIGH";
  }
  if (algorithm.startsWith("EC")) {
    return "HIGH";
  }
  if (algorithm.startsWith("AES-") || algorithm.startsWith("oct-HSM")) {
    const bits = parseInt(algorithm.replace(/[^0-9]/g, ""), 10);
    return bits >= 256 ? "LOW" : "MEDIUM";
  }
  return "MEDIUM";
}

/** True when the algorithm is already quantum-resistant. */
export function isPqReady(algorithm: string): boolean {
  if (algorithm.startsWith("AES-") || algorithm.startsWith("oct-HSM")) {
    const bits = parseInt(algorithm.replace(/[^0-9]/g, ""), 10);
    return bits >= 256;
  }
  return false;
}
