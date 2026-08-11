import { describe, it, expect } from "vitest";
import { mint, verifyHit, run, demo, inspect } from "../src/engine";

describe("canary-tokens-lab", () => {
  it("mints typed tokens", () => {
    const c = mint("url", "secret");
    expect(c.token).toContain(c.id);
    expect(c.type).toBe("url");
  });
  it("verifies hits", () => {
    const c = mint("aws", "secret");
    const a = verifyHit(c, { tokenId: c.id, at: "1970-01-01T00:00:00.000Z", userAgent: "python-requests" }, "secret");
    expect(a?.severity).toBe("critical");
  });
  it("run + demo", () => {
    expect(run({}).canaries.length).toBeGreaterThan(0);
    expect(demo().findings.length).toBeGreaterThan(0);
    expect(inspect().features).toContain("hmac");
  });
});
