import { build } from "esbuild";
import { chmodSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(packageRoot, "../..");
const internalPackages = [
  "browser-runner",
  "contracts",
  "observability",
  "saml-core",
  "scenarios",
  "target-safety",
];
const alias = Object.fromEntries(
  internalPackages.map((name) => [
    `@saml-chaos/${name}`,
    resolve(repositoryRoot, `packages/${name}/src/index.ts`),
  ]),
);
const output = resolve(process.env.SCL_CLI_OUTFILE ?? resolve(packageRoot, "dist/cli.mjs"));

await mkdir(dirname(output), { recursive: true });
await build({
  entryPoints: [resolve(packageRoot, "src/index.ts")],
  outfile: output,
  bundle: true,
  minify: true,
  platform: "node",
  format: "esm",
  target: "node20",
  packages: "external",
  external: ["@playwright/test"],
  alias,
  legalComments: "eof",
});
chmodSync(output, 0o755);

if (!process.env.SCL_CLI_OUTFILE) {
  await build({
    entryPoints: [resolve(packageRoot, "src/helpers.ts")],
    outfile: resolve(packageRoot, "dist/helpers.mjs"),
    bundle: true,
    minify: true,
    platform: "node",
    format: "esm",
    target: "node20",
    packages: "external",
    alias,
    legalComments: "eof",
  });
}
