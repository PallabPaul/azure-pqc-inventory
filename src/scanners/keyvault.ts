/**
 * Azure Key Vault scanner.
 *
 * Lists Key Vaults in a subscription via `KeyVaultManagementClient`, then for
 * each vault iterates keys via `KeyClient.listPropertiesOfKeys()` and
 * certificates via `CertificateClient.listPropertiesOfCertificates()`, and
 * classifies each as quantum-vulnerable / quantum-resistant. Also emits
 * vault-level posture findings (soft-delete, purge protection, public network
 * access, RBAC) and key/certificate hygiene findings (no rotation policy,
 * expired or stale keys, expiring certificates).
 *
 * Authentication (in order of preference):
 *   1. servicePrincipal — { tenantId, clientId, clientSecret }
 *   2. ambient          — DefaultAzureCredential (env, Managed Identity, az login, …)
 */

import {
  ClientSecretCredential,
  DefaultAzureCredential,
  type TokenCredential,
} from "@azure/identity";
import { KeyVaultManagementClient, type Vault } from "@azure/arm-keyvault";
import { KeyClient, type KeyProperties } from "@azure/keyvault-keys";
import { CertificateClient } from "@azure/keyvault-certificates";

import type { AzureAuthOptions, CryptoResource, ScannerResult } from "../types.js";
import {
  classifyRisk,
  describeCertAlgorithm,
  describeKeyAlgorithm,
  isPqReady,
} from "../classify.js";
import { redactAzureIdentifiers } from "../redact.js";

const MS_PER_DAY = 24 * 60 * 60 * 1000;
/** Flag keys that haven't been rotated in this many days. */
const KEY_AGE_WARN_DAYS = 365;
/** Flag certificates expiring within this window. */
const CERT_EXPIRY_WARN_DAYS = 30;

export interface KeyVaultScanOptions extends AzureAuthOptions {
  /** Optional vault-name allow-list. When omitted all vaults are scanned. */
  vaultNames?: string[];
  /** Flag keys older than this many days. Defaults to 365. */
  keyAgeWarnDays?: number;
}

export async function scanKeyVault(
  opts: KeyVaultScanOptions,
): Promise<ScannerResult> {
  if (!opts.subscriptionId) {
    throw new Error("Key Vault scan requires a subscription id");
  }

  const credential = resolveCredential(opts);
  const mgmt = new KeyVaultManagementClient(credential, opts.subscriptionId);

  const resources: CryptoResource[] = [];
  const scanned: string[] = [];
  const errors: { target: string; message: string }[] = [];

  // 1. Enumerate all vaults visible to this credential in the subscription.
  const vaults: { name: string; uri: string; location: string; raw: Vault }[] = [];
  for await (const v of mgmt.vaults.listBySubscription()) {
    if (!v.name || !v.properties?.vaultUri) continue;
    if (opts.vaultNames && !opts.vaultNames.includes(v.name)) continue;
    vaults.push({
      name: v.name,
      uri: v.properties.vaultUri,
      location: v.location ?? "unknown",
      raw: v,
    });
  }

  // 2. For each vault: emit posture findings, then list keys + certificates.
  for (const vault of vaults) {
    // 2a. Vault-level posture findings (no extra API calls — data is on `raw`).
    resources.push(...vaultPostureResources(vault.name, vault.location, vault.raw));

    try {
      // 2b. Keys.
      const keyClient = new KeyClient(vault.uri, credential);
      for await (const key of keyClient.listPropertiesOfKeys()) {
        // Skip keys that back a KV certificate — they show up as cert-managed
        // keys (`managed: true`) and Azure refuses direct operations on them.
        // The corresponding certificate finding already covers the key material.
        if ((key as { managed?: boolean }).managed === true) continue;

        // listPropertiesOfKeys() does NOT include kty / key size / curve —
        // those live on KeyVaultKey.key. Do an extra getKey() per listed key
        // so we can classify RSA vs EC vs oct (and emit a real key size /
        // curve name) instead of falling back to "UNKNOWN".
        let keyMaterial: { kty?: string; keySize?: number; curveName?: string } = {};
        if (key.name) {
          try {
            const full = await keyClient.getKey(key.name);
            const k = full.key ?? ({} as Record<string, unknown>);
            const n = (k as { n?: Uint8Array }).n;
            keyMaterial = {
              kty: (k as { kty?: string }).kty,
              keySize: n ? n.byteLength * 8 : undefined,
              curveName: (k as { crv?: string }).crv,
            };
          } catch {
            // getKey may be denied (separate keys/get permission); fall back to UNKNOWN.
          }
        }

        const algorithm = describeKeyAlgorithm(keyMaterial);
        resources.push({
          id: key.id ?? `${vault.uri}keys/${key.name}`,
          name: key.name ?? "unknown",
          type: "Key Vault Key",
          region: vault.location,
          algorithm,
          risk: classifyRisk(algorithm),
          pqReady: isPqReady(algorithm),
          details: keyDetails(vault.name, key, algorithm),
        });

        // Key hygiene: rotation policy + expiry / age.
        resources.push(
          ...(await keyHygieneResources(
            vault.name,
            vault.location,
            key,
            keyClient,
            opts.keyAgeWarnDays ?? KEY_AGE_WARN_DAYS,
          )),
        );
      }

      // 2c. Certificates.
      try {
        const certClient = new CertificateClient(vault.uri, credential);
        for await (const cert of certClient.listPropertiesOfCertificates()) {
          if (!cert.name) continue;
          let algorithm = "UNKNOWN";
          let keySize: number | undefined;
          try {
            const full = await certClient.getCertificate(cert.name);
            const policy = full.policy;
            algorithm = describeCertAlgorithm(
              policy?.keyType,
              policy?.keySize,
              policy?.keyCurveName,
            );
            keySize = policy?.keySize ?? undefined;
          } catch {
            // policy fetch may be denied even when listing succeeds — keep going.
          }

          resources.push({
            id: cert.id ?? `${vault.uri}certificates/${cert.name}`,
            name: cert.name,
            type: "Key Vault Certificate",
            region: vault.location,
            algorithm,
            risk: classifyRisk(algorithm),
            pqReady: isPqReady(algorithm),
            details: certDetails(vault.name, cert.name, algorithm, keySize, cert.expiresOn),
          });

          // Cert hygiene: expired / expiring soon.
          const expiry = expiryFinding(vault.name, vault.location, cert.name, cert.expiresOn);
          if (expiry) resources.push(expiry);
        }
      } catch (err) {
        // Don't fail the whole vault if cert listing is denied (separate RBAC).
        errors.push({ target: `${vault.name} (certificates)`, message: errorMessage(err) });
      }

      scanned.push(vault.name);
    } catch (err) {
      errors.push({ target: vault.name, message: errorMessage(err) });
    }
  }

  return { scanner: "keyvault", resources, scanned, errors };
}

/* ─────────────────────────── Credentials ─────────────────────────── */

function resolveCredential(opts: AzureAuthOptions): TokenCredential {
  if (opts.tenantId && opts.clientId && opts.clientSecret) {
    return new ClientSecretCredential(opts.tenantId, opts.clientId, opts.clientSecret);
  }
  // Falls back to env / Managed Identity / az login.
  return new DefaultAzureCredential();
}

/* ─────────────────────────── Details ─────────────────────────── */

function keyDetails(vaultName: string, props: KeyProperties, algorithm: string): string {
  const enabled = props.enabled === false ? " [DISABLED]" : "";
  if (algorithm.startsWith("RSA")) {
    return `Vault ${vaultName} — RSA key (${algorithm}) — quantum-vulnerable (Shor)${enabled}`;
  }
  if (algorithm.startsWith("EC")) {
    return `Vault ${vaultName} — elliptic curve key (${algorithm}) — quantum-vulnerable (Shor)${enabled}`;
  }
  if (algorithm.startsWith("AES-") || algorithm.startsWith("oct")) {
    return `Vault ${vaultName} — symmetric key (${algorithm}) — quantum-resistant under Grover${enabled}`;
  }
  return `Vault ${vaultName} — key ${algorithm}${enabled}`;
}

function certDetails(
  vaultName: string,
  certName: string,
  algorithm: string,
  keySize: number | undefined,
  expiresOn: Date | undefined,
): string {
  const sz = keySize ? ` ${keySize}-bit` : "";
  const exp = expiresOn ? ` — expires ${expiresOn.toISOString().slice(0, 10)}` : "";
  return `Vault ${vaultName} — certificate ${certName} (${algorithm}${sz})${exp}`;
}

function expiryFinding(
  vaultName: string,
  location: string,
  certName: string,
  expiresOn: Date | undefined,
): CryptoResource | null {
  if (!expiresOn) return null;
  const days = Math.floor((expiresOn.getTime() - Date.now()) / MS_PER_DAY);
  if (days >= CERT_EXPIRY_WARN_DAYS) return null;

  const expired = days < 0;
  return {
    id: `${vaultName}/cert-expiry/${certName}`,
    name: `${certName} (${expired ? "expired" : `expires in ${days}d`})`,
    type: "Certificate Hygiene",
    region: location,
    algorithm: expired ? "EXPIRED-CERT" : "EXPIRING-CERT",
    risk: expired ? "HIGH" : "MEDIUM",
    pqReady: false,
    details: `Vault ${vaultName} — certificate ${certName} ${
      expired ? `expired ${Math.abs(days)} days ago` : `expires in ${days} days`
    }; renew before it lapses.`,
  };
}

/* ─────────────────────────── Key hygiene ─────────────────────────── */

async function keyHygieneResources(
  vaultName: string,
  location: string,
  key: KeyProperties,
  client: KeyClient,
  keyAgeWarnDays = KEY_AGE_WARN_DAYS,
): Promise<CryptoResource[]> {
  const out: CryptoResource[] = [];
  const keyName = key.name ?? "unknown";

  // Expired but still enabled.
  if (key.expiresOn && key.expiresOn.getTime() < Date.now() && key.enabled !== false) {
    out.push({
      id: `${vaultName}/key-expired/${keyName}`,
      name: `${keyName} (expired)`,
      type: "Key Hygiene",
      region: location,
      algorithm: "EXPIRED-KEY",
      risk: "HIGH",
      pqReady: false,
      details: `Vault ${vaultName} — key ${keyName} expired on ${key.expiresOn
        .toISOString()
        .slice(0, 10)} but is still enabled.`,
    });
  }

  // Key older than KEY_AGE_WARN_DAYS without rotation.
  if (key.createdOn) {
    const ageDays = Math.floor((Date.now() - key.createdOn.getTime()) / MS_PER_DAY);
    if (ageDays > keyAgeWarnDays) {
      out.push({
        id: `${vaultName}/key-stale/${keyName}`,
        name: `${keyName} (${ageDays}d old)`,
        type: "Key Hygiene",
        region: location,
        algorithm: "STALE-KEY",
        risk: "MEDIUM",
        pqReady: false,
        details: `Vault ${vaultName} — key ${keyName} is ${ageDays} days old; consider rotation.`,
      });
    }
  }

  // No rotation policy attached.
  try {
    const policy = await client.getKeyRotationPolicy(keyName);
    const hasAutoRotate = (policy.lifetimeActions ?? []).some((la) => la.action === "Rotate");
    if (!hasAutoRotate) {
      out.push({
        id: `${vaultName}/key-no-rotation/${keyName}`,
        name: `${keyName} (no rotation policy)`,
        type: "Key Hygiene",
        region: location,
        algorithm: "NO-ROTATION-POLICY",
        risk: "MEDIUM",
        pqReady: false,
        details: `Vault ${vaultName} — key ${keyName} has no auto-rotation lifetime action configured.`,
      });
    }
  } catch {
    // 404 / 403 / RBAC — skip silently. Rotation policies are optional and
    // require Key Vault Crypto Officer, which is not always granted.
  }

  return out;
}

/* ─────────────────────────── Vault posture ─────────────────────────── */

interface VaultLike {
  properties?: {
    enableSoftDelete?: boolean;
    enablePurgeProtection?: boolean;
    enableRbacAuthorization?: boolean;
    publicNetworkAccess?: string;
    networkAcls?: { defaultAction?: string };
    sku?: { name?: string };
  };
}

function vaultPostureResources(
  vaultName: string,
  location: string,
  vault: VaultLike,
): CryptoResource[] {
  const out: CryptoResource[] = [];
  const props = vault.properties ?? {};

  if (props.enableSoftDelete === false) {
    out.push({
      id: `${vaultName}/posture/soft-delete`,
      name: `${vaultName} — soft-delete disabled`,
      type: "Vault Posture",
      region: location,
      algorithm: "SOFT-DELETE-OFF",
      risk: "HIGH",
      pqReady: false,
      details: `Vault ${vaultName} has soft-delete disabled. Enable it (now mandatory for new vaults) to protect against accidental key deletion.`,
    });
  }

  if (props.enablePurgeProtection !== true) {
    out.push({
      id: `${vaultName}/posture/purge-protection`,
      name: `${vaultName} — purge protection off`,
      type: "Vault Posture",
      region: location,
      algorithm: "PURGE-PROTECTION-OFF",
      risk: "MEDIUM",
      pqReady: false,
      details: `Vault ${vaultName} does not have purge protection enabled; soft-deleted keys/secrets can be permanently destroyed within the retention window.`,
    });
  }

  if (
    (props.publicNetworkAccess ?? "Enabled") === "Enabled" &&
    (props.networkAcls?.defaultAction ?? "Allow") !== "Deny"
  ) {
    out.push({
      id: `${vaultName}/posture/public-access`,
      name: `${vaultName} — public network access enabled`,
      type: "Vault Posture",
      region: location,
      algorithm: "PUBLIC-NETWORK-ACCESS",
      risk: "MEDIUM",
      pqReady: false,
      details: `Vault ${vaultName} is reachable from the public internet (no Private Endpoint or default-deny firewall). Restrict via Private Endpoint or network ACLs.`,
    });
  }

  if (props.enableRbacAuthorization !== true) {
    out.push({
      id: `${vaultName}/posture/rbac`,
      name: `${vaultName} — legacy access policies`,
      type: "Vault Posture",
      region: location,
      algorithm: "LEGACY-ACCESS-POLICIES",
      risk: "LOW",
      pqReady: false,
      details: `Vault ${vaultName} uses legacy access policies instead of Azure RBAC. Migrate to RBAC for fine-grained, auditable permissions.`,
    });
  }

  return out;
}

function errorMessage(err: unknown): string {
  return redactAzureIdentifiers(err instanceof Error ? err.message : String(err));
}
