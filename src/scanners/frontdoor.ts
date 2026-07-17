/**
 * Azure Front Door (Standard / Premium) TLS posture scanner.
 *
 * For each Front Door profile in the subscription, lists every custom domain
 * and emits a finding describing its TLS posture:
 *
 *   - minimumTlsVersion === TLS10         → HIGH (TLS-1.0-MIN)
 *   - CustomerCertificate (from Key Vault) → HIGH (classical leaf in production)
 *   - ManagedCertificate (Front Door)      → HIGH (classical managed leaf)
 *
 * Authentication: service principal triple OR DefaultAzureCredential.
 */

import {
  ClientSecretCredential,
  DefaultAzureCredential,
  type TokenCredential,
} from "@azure/identity";
import { CdnManagementClient } from "@azure/arm-cdn";

import type { AzureAuthOptions, CryptoResource, ScannerResult } from "../types.js";
import { redactAzureIdentifiers } from "../redact.js";
import { probeTls } from "./appservice.js";

export interface FrontDoorScanOptions extends AzureAuthOptions {
  resourceGroups?: string[];
  tlsTimeoutMs?: number;
}

export async function scanFrontDoor(
  opts: FrontDoorScanOptions,
): Promise<ScannerResult> {
  if (!opts.subscriptionId) {
    throw new Error("Front Door scan requires a subscription id");
  }
  const credential = resolveCredential(opts);
  const client = new CdnManagementClient(credential, opts.subscriptionId);

  const resources: CryptoResource[] = [];
  const scanned: string[] = [];
  const errors: { target: string; message: string }[] = [];

  for await (const profile of client.profiles.list()) {
    if (!profile.name || !profile.id) continue;
    const sku = profile.sku?.name ?? "";
    // Only Front Door Standard / Premium expose the per-domain cert model.
    if (sku !== "Standard_AzureFrontDoor" && sku !== "Premium_AzureFrontDoor") continue;

    const rg = parseResourceGroup(profile.id);
    if (!rg) continue;
    if (opts.resourceGroups && !opts.resourceGroups.includes(rg)) continue;

    const profileName = profile.name;
    const region = profile.location ?? "global";

    try {
      for await (const domain of client.afdCustomDomains.listByProfile(rg, profileName)) {
        if (!domain.name || !domain.id) continue;
        const hostName = domain.hostName ?? domain.name;
        const tls = domain.tlsSettings;
        const certType = tls?.certificateType;
        const minTls = tls?.minimumTlsVersion ?? "TLS12";
        const baseDetails = `Front Door profile ${profileName} → custom domain ${hostName}.`;

        // 1. Minimum TLS version posture finding (independent of cert type).
        if (minTls === "TLS10") {
          resources.push({
            id: `${domain.id}/posture/min-tls`,
            name: `${profileName}/${hostName} — min TLS 1.0`,
            type: "Front Door custom domain",
            region,
            algorithm: "TLS-1.0-MIN",
            risk: "HIGH",
            pqReady: false,
            details: `${baseDetails} Minimum TLS version is 1.0 — raise to 1.2 in the domain TLS settings.`,
          });
        }

        // 2. Live certificate / handshake posture. The management API does
        // not expose the leaf algorithm, so never invent ECDHE-RSA metadata.
        const probe = await probeTls(hostName, opts.tlsTimeoutMs ?? 5000);
        if (probe) {
          const vulnerable =
            probe.keyAlgorithm.startsWith("RSA") ||
            probe.keyAlgorithm.startsWith("EC");
          resources.push({
            id: `${domain.id}/tls/handshake`,
            name: `${profileName}/${hostName} — TLS handshake`,
            type: "Front Door custom domain",
            region,
            algorithm: `${probe.protocol} (${probe.keyAlgorithm})`,
            risk: vulnerable ? "HIGH" : "MEDIUM",
            pqReady: !vulnerable && probe.keyAlgorithm !== "UNKNOWN",
            details:
              `${baseDetails} Live handshake negotiated ${probe.protocol} / ${probe.cipher}; ` +
              `leaf certificate public key ${probe.keyAlgorithm}.`,
          });
        } else {
          resources.push({
            id: `${domain.id}/tls/handshake`,
            name: `${profileName}/${hostName} — TLS handshake`,
            type: "Front Door custom domain",
            region,
            algorithm: "UNKNOWN",
            risk: "MEDIUM",
            pqReady: false,
            details: `${baseDetails} The live TLS probe was unavailable and Azure does not expose the leaf algorithm in this API response (certificate type: ${certType ?? "managed"}).`,
          });
        }
      }

      scanned.push(profileName);
    } catch (err) {
      errors.push({ target: profileName, message: errorMessage(err) });
    }
  }

  return { scanner: "frontdoor", resources, scanned, errors };
}

function resolveCredential(opts: AzureAuthOptions): TokenCredential {
  if (opts.tenantId && opts.clientId && opts.clientSecret) {
    return new ClientSecretCredential(opts.tenantId, opts.clientId, opts.clientSecret);
  }
  return new DefaultAzureCredential();
}

function parseResourceGroup(armId: string): string | null {
  const m = /\/resourceGroups\/([^/]+)/i.exec(armId);
  return m?.[1] ?? null;
}

function errorMessage(err: unknown): string {
  return redactAzureIdentifiers(err instanceof Error ? err.message : String(err));
}
