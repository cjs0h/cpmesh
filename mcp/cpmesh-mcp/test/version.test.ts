import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("version", () => {
  it("reports the version being published", () => {
    const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    const source = readFileSync(new URL("../src/index.ts", import.meta.url), "utf8");
    expect(source).toContain(`const VERSION = "${version}";`);
  });
});
