/**
 * Azure App Service / Function App TLS posture scanner.
 *
 * Lists every Web/Function app in the subscription and emits findings for:
 *   - minTlsVersion < 1.2  → HIGH (TLS-1.0-MIN / TLS-1.1-MIN)
 *   - httpsOnly !== true   → HIGH (HTTPS-NOT-ENFORCED)
 *   - ftpsState AllAllowed (plain FTP) → MEDIUM (FTP-ENABLED)
 *
 * For every publicly-reachable app it also performs a best-effort live TLS
 * handshake against the app's hostname, reporting the negotiated protocol,
 * cipher suite, and the leaf certificate's public-key algorithm. Any classical
 * (RSA / EC) key-exchange or certificate key is flagged as quantum-vulnerable.
 *
 * Authentication: service principal triple OR DefaultAzureCredential.
 */

import {
  ClientSecretCredential,
  DefaultAzureCredential,
  type TokenCredential,
} from "@azure/identity";
import { WebSiteManagementClient } from "@azure/arm-appservice";
import tls from "node:tls";

import type { AzureAuthOptions, CryptoResource, ScannerResult } from "../types.js";

export interface AppServiceScanOptions extends AzureAuthOptions {
  /** Optional resource-group filter. */
  resourceGroups?: string[];
}

export async function scanAppService(
  opts: AppServiceScanOptions,
): Promise<ScannerResult> {
  if (!opts.subscriptionId) {
    throw new Error("App Service scan requires a subscription id");
  }

  const credential = resolveCredential(opts);
  const client = new WebSiteManagementClient(credential, opts.subscriptionId);

  const resources: CryptoResource[] = [];
  const scanned: string[] = [];
  const errors: { target: string; message: string }[] = [];

  for await (const site of client.webApps.list()) {
    if (!site.name || !site.id) continue;
    if (
      opts.resourceGroups &&
      (!site.resourceGroup || !opts.resourceGroups.includes(site.resourceGroup))
    ) {
      continue;
    }

    const appName = site.name;
    const region = site.location ?? "unknown";
    const rg = site.resourceGroup ?? "unknown";

    try {
      const config = await client.webApps.getConfiguration(rg, appName);

      // 1. Minimum TLS version.
      const minTls = (config.minTlsVersion ?? "").toString();
      if (minTls === "1.0" || minTls === "1.1") {
        resources.push({
          id: `${site.id}/posture/min-tls`,
          name: `${appName} — min TLS ${minTls}`,
          type: "App Service",
          region,
          algorithm: minTls === "1.0" ? "TLS-1.0-MIN" : "TLS-1.1-MIN",
          risk: "HIGH",
          pqReady: false,
          details: `App Service ${appName} accepts TLS ${minTls} as minimum. Set Minimum TLS Version to 1.2 (or 1.3) in TLS/SSL settings.`,
        });
      }

      // 2. HTTPS-only enforcement.
      if (site.httpsOnly !== true) {
        resources.push({
          id: `${site.id}/posture/https-only`,
          name: `${appName} — HTTPS not enforced`,
          type: "App Service",
          region,
          algorithm: "HTTPS-NOT-ENFORCED",
          risk: "HIGH",
          pqReady: false,
          details: `App Service ${appName} accepts plain HTTP requests. Enable "HTTPS Only" so all traffic is redirected to TLS.`,
        });
      }

      // 3. FTP / FTPS state.
      const ftps = (config.ftpsState ?? "").toString();
      if (ftps === "AllAllowed") {
        resources.push({
          id: `${site.id}/posture/ftp`,
          name: `${appName} — plain FTP enabled`,
          type: "App Service",
          region,
          algorithm: "FTP-ENABLED",
          risk: "MEDIUM",
          pqReady: false,
          details: `App Service ${appName} accepts unencrypted FTP for deployments. Disable FTP or restrict to FTPS only.`,
        });
      }

      // 4. Live TLS handshake against a public hostname.
      const isPublic =
        (site.publicNetworkAccess ?? "Enabled") === "Enabled" &&
        !(site.virtualNetworkSubnetId ?? "").length;
      if (isPublic) {
        const probeHost = pickProbeHostname(site.hostNames, site.defaultHostName);
        const probe = probeHost ? await probeTls(probeHost) : null;
        if (probe) {
          const vulnerable = probe.keyAlgorithm.startsWith("RSA") || probe.keyAlgorithm.startsWith("EC");
          resources.push({
            id: `${site.id}/tls/handshake`,
            name: `${appName} — TLS handshake`,
            type: "App Service",
            region,
            algorithm: `${probe.protocol} (${probe.keyAlgorithm})`,
            risk: vulnerable ? "HIGH" : "LOW",
            pqReady: !vulnerable,
            details:
              `App Service ${appName} (${probeHost}) negotiated ${probe.protocol} / ${probe.cipher}; ` +
              `leaf certificate public key ${probe.keyAlgorithm}` +
              (vulnerable
                ? " — classical key exchange is quantum-vulnerable (harvest-now-decrypt-later surface)."
                : "."),
          });
        }
      }

      scanned.push(appName);
    } catch (err) {
      errors.push({ target: appName, message: errorMessage(err) });
    }
  }

  return { scanner: "appservice", resources, scanned, errors };
}

function resolveCredential(opts: AzureAuthOptions): TokenCredential {
  if (opts.tenantId && opts.clientId && opts.clientSecret) {
    return new ClientSecretCredential(opts.tenantId, opts.clientId, opts.clientSecret);
  }
  return new DefaultAzureCredential();
}

/**
 * Prefer a custom (verified) hostname over the default `*.azurewebsites.net`
 * so the probe sees the customer's actual leaf certificate.
 */
function pickProbeHostname(
  hostNames: string[] | undefined,
  defaultHost: string | undefined,
): string | null {
  const custom = (hostNames ?? []).find((h) => h && !h.endsWith(".azurewebsites.net"));
  return custom || defaultHost || null;
}

interface TlsProbe {
  protocol: string;
  cipher: string;
  keyAlgorithm: string;
}

/**
 * Open a TLS connection to `host:443`, read the negotiated protocol / cipher
 * and the peer leaf certificate's public-key algorithm, then close. Returns
 * null on any error or timeout — a probe failure must never abort the scan.
 */
function probeTls(host: string): Promise<TlsProbe | null> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (out: TlsProbe | null) => {
      if (done) return;
      done = true;
      try {
        socket.destroy();
      } catch {
        /* noop */
      }
      resolve(out);
    };

    const socket = tls.connect(
      {
        host,
        port: 443,
        servername: host,
        // We just want handshake metadata; don't fail on chain issues.
        rejectUnauthorized: false,
        ALPNProtocols: ["http/1.1"],
      },
      () => {
        try {
          const protocol = socket.getProtocol() ?? "unknown";
          const cipher = socket.getCipher()?.name ?? "unknown";
          const peer = socket.getPeerCertificate(false) as {
            bits?: number;
            modulus?: string;
            nistCurve?: string;
            asn1Curve?: string;
          };
          finish({ protocol, cipher, keyAlgorithm: describePeerKey(peer) });
        } catch {
          finish(null);
        }
      },
    );
    socket.setTimeout(5000, () => finish(null));
    socket.on("error", () => finish(null));
  });
}

/** Derive an algorithm string from a Node TLS peer-certificate object. */
function describePeerKey(peer: {
  bits?: number;
  modulus?: string;
  nistCurve?: string;
  asn1Curve?: string;
}): string {
  if (peer.modulus) {
    const bits = peer.bits ?? peer.modulus.length * 4;
    return `RSA-${bits}`;
  }
  const curve = peer.nistCurve || peer.asn1Curve;
  if (curve) {
    return `EC-${curve.replace(/^P-/, "P")}`;
  }
  return "UNKNOWN";
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
