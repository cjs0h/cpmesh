import { build } from "esbuild";
import { rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";

// This package is a CLI, not a typed library. Bundle only our sources and keep
// dependencies external, with the same Node 18 runtime target as the published bin.
const output = new URL("../dist/index.js", import.meta.url);
await Promise.all(["index.d.ts", "index.d.cts"].map((name) =>
  rm(new URL(`../dist/${name}`, import.meta.url), { force: true }),
));
await build({
  entryPoints: [fileURLToPath(new URL("../src/index.ts", import.meta.url))],
  outfile: fileURLToPath(output),
  bundle: true,
  packages: "external",
  format: "esm",
  platform: "node",
  target: "node18",
  sourcemap: true,
  banner: { js: "#!/usr/bin/env node" },
});
