/**
 * Shared types for the Azure post-quantum inventory scanner.
 */

/** Relative quantum / hygiene risk of a discovered resource. */
export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

/**
 * A single discovered cryptographic resource or posture finding.
 *
 * `algorithm` carries either a real algorithm string (e.g. `RSA-2048`,
 * `EC-P256`, `AES-256`) or a synthetic marker for a posture/hygiene finding
 * (e.g. `SOFT-DELETE-OFF`, `EXPIRED-CERT`, `TLS-1.0-MIN`).
 */
export interface CryptoResource {
  /** Stable identifier (ARM id where available, otherwise a synthetic key). */
  id: string;
  /** Short display name. */
  name: string;
  /** Resource / finding category, e.g. "Key Vault Key", "App Service". */
  type: string;
  /** Azure region / location, or "global". */
  region: string;
  /** Algorithm string or synthetic posture marker. */
  algorithm: string;
  /** Quantum / hygiene risk classification. */
  risk: RiskLevel;
  /** True when the resource is already quantum-resistant. */
  pqReady: boolean;
  /** Human-readable explanation + remediation hint. */
  details: string;
}

/** Common authentication + scope options shared by every scanner. */
export interface AzureAuthOptions {
  /** Subscription to enumerate. Required. */
  subscriptionId: string;
  /** Service-principal auth (otherwise DefaultAzureCredential is used). */
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
}

/** Result envelope returned by each scanner. */
export interface ScannerResult {
  /** Which scanner produced this result. */
  scanner: "keyvault" | "appservice" | "frontdoor";
  /** Discovered resources + posture findings. */
  resources: CryptoResource[];
  /** Names of the top-level objects that were scanned (vaults / apps / profiles). */
  scanned: string[];
  /** Per-object errors that did not abort the whole scan. */
  errors: { target: string; message: string }[];
}
