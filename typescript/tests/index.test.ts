import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { ApprovalStore, ConflictError, ValidationError, actionDigest, createDecision, validate } from "../src/index.js";

const example = (name: string) => JSON.parse(readFileSync(resolve(import.meta.dirname, "../../examples", name), "utf8"));

describe("AAIS", () => {
  it("validates the shared request and digest", () => {
    const request = example("shell-approval.json");
    expect(actionDigest(request.request.action)).toBe(request.request.action_digest);
    expect(validate(request)).toEqual(request);
  });

  it("canonicalizes key order", () => {
    expect(actionDigest({ b: 2, a: 1 })).toBe(actionDigest({ a: 1, b: 2 }));
  });

  it("resolves and replays an identical decision", () => {
    const store = new ApprovalStore();
    store.add(example("shell-approval.json"));
    const decision = example("approve-once.json");
    const first = store.decide(decision, { now: new Date("2026-08-30T18:01:00Z") });
    expect(store.decide(decision)).toEqual(first);
    expect((first.resolution as Record<string, unknown>).outcome).toBe("approved");
  });

  it("rejects a conflicting retry", () => {
    const request = example("shell-approval.json");
    const store = new ApprovalStore(); store.add(request);
    const first = example("approve-once.json"); store.decide(first, { now: new Date("2026-08-30T18:01:00Z") });
    const second = structuredClone(first); second.decision.id = "dec_2"; second.decision.decision = "deny";
    expect(() => store.decide(second)).toThrow(ConflictError);
  });

  it("fails closed for expiry and unoffered scope", () => {
    const request = example("shell-approval.json");
    const expired = new ApprovalStore(); expired.add(request);
    expect((expired.decide(example("approve-once.json"), { now: new Date("2026-08-30T19:00:00Z") }).resolution as Record<string, unknown>).outcome).toBe("expired");
    const store = new ApprovalStore(); store.add(request);
    const unoffered = createDecision(request, { decision: "approve", scope: "persistent", actor: { id: "alex", type: "human" }, sequence: 42, decidedAt: "2026-08-30T18:01:00Z" });
    expect((store.decide(unoffered, { now: new Date("2026-08-30T18:01:00Z") }).resolution as Record<string, unknown>).outcome).toBe("invalid");
  });

  it("restores pending approvals from a snapshot", () => {
    const store = new ApprovalStore(); store.add(example("shell-approval.json"));
    const at = new Date("2026-08-30T18:01:00Z");
    expect((ApprovalStore.fromSnapshot(store.snapshot(undefined, at)).snapshot(undefined, at).snapshot as { pending: unknown[] }).pending).toHaveLength(1);
  });

  it("rejects an incorrect digest", () => {
    const request = example("shell-approval.json"); request.request.action_digest = `sha256:${"0".repeat(64)}`;
    expect(() => validate(request)).toThrow(ValidationError);
  });
});
