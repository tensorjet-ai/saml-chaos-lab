import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

export default defineConfig({
  resolve: {
    alias: {
      "@saml-chaos/contracts": resolve(__dirname, "packages/contracts/src/index.ts"),
      "@saml-chaos/target-safety": resolve(__dirname, "packages/target-safety/src/index.ts"),
      "@saml-chaos/saml-core": resolve(__dirname, "packages/saml-core/src/index.ts"),
      "@saml-chaos/scenarios": resolve(__dirname, "packages/scenarios/src/index.ts"),
      "@saml-chaos/observability": resolve(__dirname, "packages/observability/src/index.ts"),
      "@saml-chaos/browser-runner": resolve(__dirname, "packages/browser-runner/src/index.ts"),
      "saml-chaos-lab/helpers": resolve(__dirname, "packages/cli/src/helpers.ts"),
      "saml-chaos-lab": resolve(__dirname, "packages/cli/src/index.ts"),
    },
  },
  test: { globals: false, testTimeout: 15_000 },
});
