import test from "node:test";
import assert from "node:assert/strict";

import { redactAzureIdentifiers } from "./redact.js";

test("Azure errors redact subscription, resource group, vault, and GUID identifiers", () => {
  const input =
    "Denied /subscriptions/11111111-2222-4333-8444-555555555555/" +
    "resourceGroups/secret-rg/providers/Microsoft.KeyVault/vaults/x " +
    "at https://customer-prod.vault.azure.net tenant " +
    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
  const output = redactAzureIdentifiers(input);
  assert.doesNotMatch(output, /secret-rg|customer-prod|11111111|aaaaaaaa/i);
  assert.match(output, /\[REDACTED\]/);
});