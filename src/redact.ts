/** Remove tenant-specific Azure identifiers from errors safe to print in CI. */
export function redactAzureIdentifiers(message: string): string {
  return message
    .replace(/\/subscriptions\/[^/\s]+/gi, "/subscriptions/[REDACTED]")
    .replace(/\/resourceGroups\/[^/\s]+/gi, "/resourceGroups/[REDACTED]")
    .replace(/https:\/\/[^./\s]+\.vault\.azure\.net/gi, "https://[REDACTED].vault.azure.net")
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, "[REDACTED-GUID]");
}