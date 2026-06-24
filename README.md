# azure-pqc-inventory

A command-line tool that scans your Azure environment for **quantum-vulnerable cryptography** and produces a post-quantum (PQC) readiness inventory.

It enumerates cryptographic material and TLS posture across three Azure services and classifies every finding by quantum risk:

- **Azure Key Vault** — keys and certificates (RSA / EC / symmetric), plus vault posture and key/certificate hygiene.
- **Azure App Service / Function Apps** — minimum TLS version, HTTPS enforcement, FTP exposure, and a live TLS handshake probe.
- **Azure Front Door (Standard / Premium)** — custom-domain TLS posture and certificate type.

Everything runs read-only against your own subscription. The tool never modifies resources and never reads secret/key *values* — only metadata.

---

## Why post-quantum?

A cryptographically-relevant quantum computer running **Shor's algorithm** breaks the math behind today's public-key cryptography:

| Primitive | Quantum impact | Verdict |
|---|---|---|
| RSA (any size) | Broken by Shor | Quantum-vulnerable |
| Elliptic curve (ECDSA / ECDH, all curves) | Broken by Shor | Quantum-vulnerable |
| AES-256 and other ≥256-bit symmetric keys | Only weakened by Grover (halves key strength) | Quantum-resistant |

Even before such a machine exists, **harvest-now-decrypt-later** means encrypted traffic and signatures captured today can be broken retroactively. The first step to migrating is knowing exactly where classical cryptography lives — this tool builds that inventory for Azure.

---

## What it reports

### Key Vault
- **Keys** — classified as `RSA-*`, `EC-*`, `AES-*` (incl. HSM-backed variants). RSA/EC are flagged quantum-vulnerable; AES-256 is quantum-ready.
- **Certificates** — public-key algorithm and size, with expiry.
- **Vault posture** — soft-delete disabled, purge protection off, public network access, legacy access policies (vs. Azure RBAC).
- **Key hygiene** — expired-but-enabled keys, stale keys (>365 days), missing auto-rotation policy.
- **Certificate hygiene** — expired or expiring within 30 days.

### App Service / Function Apps
- Minimum TLS version `1.0` / `1.1`.
- HTTPS-only not enforced.
- Plain FTP enabled.
- Live TLS handshake: negotiated protocol, cipher, and leaf-certificate key algorithm.

### Front Door (Standard / Premium)
- Custom-domain minimum TLS version `1.0`.
- Customer vs. managed certificate, classified as classical (quantum-vulnerable) key exchange.

---

## Requirements

- **Node.js 20+**
- An **Azure subscription** and credentials with read access (see [Authentication](#authentication)).
- Network egress to Azure management endpoints (and to app hostnames on port 443 for the App Service TLS probe).

---

## Installation

```bash
git clone https://github.com/PallabPaul/azure-pqc-inventory.git
cd azure-pqc-inventory
npm install
npm run build
```

This produces a runnable CLI at `dist/cli.js`. You can either:

```bash
# run the built binary
node dist/cli.js --help

# or link it onto your PATH as `azure-pqc-inventory`
npm link
azure-pqc-inventory --help
```

For local development without building, run the TypeScript directly:

```bash
npm run dev -- --help
```

---

## Authentication

The tool uses the standard Azure identity chain. You have two options.

### Option A — Azure CLI sign-in (easiest)

If you are signed in with the Azure CLI, no extra configuration is needed:

```bash
az login
az account set --subscription "<subscription-id>"

azure-pqc-inventory --subscription "<subscription-id>"
```

`DefaultAzureCredential` automatically picks up your `az login` session, environment variables, or a Managed Identity when running inside Azure.

### Option B — Service principal

Create a dedicated read-only service principal and pass its credentials via flags or environment variables.

```bash
# 1. Create a service principal (no role yet)
az ad sp create-for-rbac --name "azure-pqc-inventory" --skip-assignment

# Note the appId (client id), password (client secret), and tenant from the output.

SUBSCRIPTION_ID="<subscription-id>"
SP_APP_ID="<appId>"

# 2. Grant least-privilege read roles at subscription scope
az role assignment create --assignee "$SP_APP_ID" \
  --role "Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID"

az role assignment create --assignee "$SP_APP_ID" \
  --role "Key Vault Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID"
```

Then run:

```bash
export AZURE_SUBSCRIPTION_ID="<subscription-id>"
export AZURE_TENANT_ID="<tenant-id>"
export AZURE_CLIENT_ID="<appId>"
export AZURE_CLIENT_SECRET="<password>"

azure-pqc-inventory
```

### Required roles

| Role | Scope | Needed for |
|---|---|---|
| **Reader** | Subscription | Enumerating vaults, app services, and Front Door profiles |
| **Key Vault Reader** | Subscription or vault | Listing keys & certificates (metadata) |
| **Key Vault Crypto Officer** *(optional)* | Vault | Reading key auto-rotation policies (otherwise that one hygiene check is skipped) |

> The tool only reads metadata. It never calls `getSecret`, never exports private keys, and never writes to any resource. If a particular permission is missing, that finding is skipped and the scan continues.

---

## Usage

```text
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

OUTPUT
  --json                     Emit the report as JSON
  --output <file>            Write the report to a file instead of stdout
  --fail-on <level>          Exit 2 if any finding is at or above this severity
                             (CRITICAL | HIGH | MEDIUM | LOW)
  --no-color                 Disable ANSI colour
  -h, --help                 Show help
  -v, --version              Show version
```

### Examples

```bash
# Scan everything in a subscription using your az login session
azure-pqc-inventory --subscription 00000000-0000-0000-0000-000000000000

# Only Key Vault, limited to two vaults
azure-pqc-inventory --keyvault --vault prod-kv --vault payments-kv

# App Service + Front Door in specific resource groups
azure-pqc-inventory --appservice --frontdoor \
  --resource-group rg-web --resource-group rg-edge

# JSON report to a file (machine-readable)
azure-pqc-inventory --json --output inventory.json

# CI gate: fail the build if any HIGH or CRITICAL finding exists
azure-pqc-inventory --subscription "$AZURE_SUBSCRIPTION_ID" --fail-on HIGH
```

---

## Output

### Human-readable (default)

Findings are grouped by severity (most severe first), each with its type, region, algorithm, and a remediation hint, followed by a summary and an overall **quantum risk score** (0–100).

### JSON (`--json`)

```jsonc
{
  "generatedAt": "2026-06-24T12:00:00.000Z",
  "subscriptionId": "00000000-0000-0000-0000-000000000000",
  "riskScore": 64,
  "riskLevel": "HIGH",
  "totals": {
    "resources": 42,
    "quantumVulnerable": 28,
    "quantumReady": 6,
    "bySeverity": { "CRITICAL": 0, "HIGH": 18, "MEDIUM": 7, "LOW": 11, "NONE": 6 }
  },
  "scanners": [
    { "name": "keyvault", "scanned": ["prod-kv"], "errors": [] }
  ],
  "resources": [
    {
      "id": "https://prod-kv.vault.azure.net/keys/signing-key",
      "name": "signing-key",
      "type": "Key Vault Key",
      "region": "eastus",
      "algorithm": "RSA-2048",
      "risk": "HIGH",
      "pqReady": false,
      "details": "Vault prod-kv — RSA key (RSA-2048) — quantum-vulnerable (Shor)"
    }
  ]
}
```

---

## Risk scoring

Each finding contributes a weight to a capped 0–100 score:

| Severity | Weight |
|---|---|
| CRITICAL | 40 |
| HIGH | 20 |
| MEDIUM | 8 |
| LOW | 2 |
| NONE | 0 |

The overall level is derived from the total score: `≥80 CRITICAL`, `≥60 HIGH`, `≥40 MEDIUM`, `≥20 LOW`, else `NONE`.

---

## Findings reference

| Marker | Severity | Meaning |
|---|---|---|
| `RSA-*` (≤3072) | HIGH | RSA key/cert — broken by Shor |
| `RSA-4096` / `RSA-HSM-*` | MEDIUM | RSA with a longer migration runway |
| `EC-*` | HIGH | Elliptic-curve key/cert — broken by Shor |
| `AES-256` / `oct-HSM-256` | LOW | Symmetric ≥256-bit — quantum-resistant |
| `EXPIRED-KEY` / `EXPIRED-CERT` | HIGH | Expired but still present |
| `EXPIRING-CERT` | MEDIUM | Certificate expiring within 30 days |
| `STALE-KEY` | MEDIUM | Key older than 365 days without rotation |
| `NO-ROTATION-POLICY` | MEDIUM | Key has no auto-rotation lifetime action |
| `SOFT-DELETE-OFF` | HIGH | Vault soft-delete disabled |
| `PURGE-PROTECTION-OFF` | MEDIUM | Vault purge protection disabled |
| `PUBLIC-NETWORK-ACCESS` | MEDIUM | Vault reachable from the public internet |
| `LEGACY-ACCESS-POLICIES` | LOW | Vault uses legacy access policies, not RBAC |
| `TLS-1.0-MIN` / `TLS-1.1-MIN` | HIGH | Endpoint accepts legacy TLS |
| `HTTPS-NOT-ENFORCED` | HIGH | App accepts plain HTTP |
| `FTP-ENABLED` | MEDIUM | App accepts unencrypted FTP |

---

## CI integration

Use `--fail-on` to turn the scan into a pipeline gate. The process exits `2` when a finding at or above the threshold is present, `1` on error, and `0` otherwise.

```yaml
# GitHub Actions example
- name: Azure PQC inventory
  env:
    AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
    AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
    AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
  run: |
    npm ci
    npm run build
    node dist/cli.js --json --output inventory.json --fail-on HIGH
```

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `no subscription id` | Pass `--subscription` or set `AZURE_SUBSCRIPTION_ID`. |
| `AuthenticationRequiredError` / credential errors | Run `az login`, or set the `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` trio. |
| Keys listed but algorithm shows `UNKNOWN` | The credential can list keys but not read key material — grant **Key Vault Reader**. |
| Rotation-policy checks missing | Optional **Key Vault Crypto Officer** is required to read rotation policies; otherwise that check is skipped. |
| App Service TLS handshake missing for an app | The app is private (VNet-integrated or public access disabled) or unreachable on 443; only management-plane posture checks apply. |

---

## License

[MIT](LICENSE)
