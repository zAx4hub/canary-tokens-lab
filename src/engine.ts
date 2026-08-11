/** canary-tokens-lab — self-host canaries by zAx4hub */
import { createHmac, randomBytes, createHash } from "crypto";

export type TokenType = "url" | "aws" | "doc" | "dns";
export type Canary = { id: string; type: TokenType; token: string; createdAt: string; meta?: Record<string, string> };
export type Hit = { tokenId: string; at: string; sourceIp?: string; userAgent?: string; path?: string };
export type Alert = { id: string; tokenId: string; severity: "critical" | "high" | "medium"; score: number; reason: string };

export type Report = {
  project: string;
  author: string;
  summary: string;
  score: number;
  findings: Alert[];
  canaries: Canary[];
  metrics: Record<string, number>;
};

export function mint(type: TokenType, secret: string, meta: Record<string, string> = {}): Canary {
  const id = randomBytes(6).toString("hex");
  const sig = createHmac("sha256", secret).update(`${type}:${id}`).digest("hex").slice(0, 24);
  let token = "";
  if (type === "url") token = `https://canary.local/t/${id}/${sig}`;
  else if (type === "aws") token = `AKIA${sig.slice(0, 16).toUpperCase()}`;
  else if (type === "dns") token = `${id}.${sig.slice(0, 8)}.canary.local`;
  else token = `CANARY-DOC-${id}-${sig}`;
  return { id, type, token, createdAt: new Date(0).toISOString(), meta };
}

export function verifyHit(canary: Canary, hit: Hit, secret: string): Alert | null {
  if (hit.tokenId !== canary.id) return null;
  const expectSig = createHmac("sha256", secret).update(`${canary.type}:${canary.id}`).digest("hex").slice(0, 24);
  const tokenOk =
    canary.token.includes(canary.id) ||
    canary.token.toUpperCase().includes(expectSig.slice(0, 8).toUpperCase()) ||
    canary.token.includes(expectSig.slice(0, 8));
  if (!tokenOk) return null;
  const ua = (hit.userAgent ?? "").toLowerCase();
  let severity: Alert["severity"] = "medium";
  let score = 0.5;
  if (canary.type === "aws" || /curl|python-requests|exfil/.test(ua)) {
    severity = "critical";
    score = 1;
  } else if (canary.type === "url") {
    severity = "high";
    score = 0.8;
  }
  return {
    id: createHash("sha1").update(`${canary.id}:${hit.at}`).digest("hex").slice(0, 10),
    tokenId: canary.id,
    severity,
    score,
    reason: `Canary ${canary.type} touched from ${hit.sourceIp ?? "unknown"}`,
  };
}

export function run(input: { secret?: string; types?: TokenType[]; hits?: Array<Partial<Hit> & { type?: TokenType }> } = {}): Report {
  const secret = input.secret ?? "zax-canary-lab";
  const types = input.types?.length ? input.types : (["url", "aws", "doc"] as TokenType[]);
  const canaries = types.map((t) => mint(t, secret, { owner: "zAx4hub" }));
  const hits: Hit[] = (input.hits ?? [{ type: "aws", sourceIp: "203.0.113.9", userAgent: "python-requests/2.0" }]).map((h, i) => {
    const c = canaries.find((x) => x.type === (h.type ?? types[0])) ?? canaries[0];
    return { tokenId: c.id, at: new Date(i * 1000).toISOString(), sourceIp: h.sourceIp, userAgent: h.userAgent, path: h.path };
  });
  const findings = hits
    .map((h) => {
      const c = canaries.find((x) => x.id === h.tokenId)!;
      return verifyHit(c, h, secret);
    })
    .filter((a): a is Alert => !!a);
  const score = findings.length ? Math.round((findings.reduce((a, f) => a + f.score, 0) / findings.length) * 1000) / 1000 : 0;
  return {
    project: "canary-tokens-lab",
    author: "zAx4hub",
    summary: `Minted ${canaries.length} canaries; alerts=${findings.length}`,
    score,
    findings,
    canaries,
    metrics: { canaries: canaries.length, alerts: findings.length, critical: findings.filter((f) => f.severity === "critical").length },
  };
}

export function demo(): Report {
  return run({
    types: ["url", "aws", "dns", "doc"],
    hits: [
      { type: "url", sourceIp: "198.51.100.4", userAgent: "Mozilla/5.0" },
      { type: "aws", sourceIp: "203.0.113.10", userAgent: "aws-cli/2" },
    ],
  });
}

export function inspect() {
  return {
    name: "canary-tokens-lab",
    author: "zAx4hub",
    oneLiner: "Self-host canary tokens",
    features: ["mint", "hmac", "hit-verify", "alerts", "types"],
    version: "0.1.0",
    commands: ["demo", "run", "inspect"],
  };
}
