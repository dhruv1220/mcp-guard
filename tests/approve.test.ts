import { describe, expect, it } from "vitest";
import {
  createApprover,
  parseApprovalAnswer,
} from "../src/gateway/approve.js";

describe("parseApprovalAnswer", () => {
  it("accepts y/yes/once, a/always, n/no, x/never (case-insensitive, trimmed)", () => {
    expect(parseApprovalAnswer("y")).toBe("once");
    expect(parseApprovalAnswer(" YES ")).toBe("once");
    expect(parseApprovalAnswer("once")).toBe("once");
    expect(parseApprovalAnswer("a")).toBe("always");
    expect(parseApprovalAnswer("Always")).toBe("always");
    expect(parseApprovalAnswer("n")).toBe("deny-once");
    expect(parseApprovalAnswer("No")).toBe("deny-once");
    expect(parseApprovalAnswer("x")).toBe("never");
    expect(parseApprovalAnswer("never")).toBe("never");
  });

  it("rejects anything else", () => {
    expect(parseApprovalAnswer("maybe")).toBeNull();
    expect(parseApprovalAnswer("")).toBeNull();
    expect(parseApprovalAnswer("yea")).toBeNull();
  });
});

describe("createApprover", () => {
  const args = { path: "/safe/a.txt" };

  it("approves on yes", async () => {
    const approver = createApprover({ prompt: async () => "y" });
    const out = await approver.ask("files", "read_file", args);
    expect(out.allowed).toBe(true);
    expect(out.reason).toContain("approved by operator");
  });

  it("denies on no", async () => {
    const approver = createApprover({ prompt: async () => "n" });
    const out = await approver.ask("files", "delete_file", args);
    expect(out.allowed).toBe(false);
    expect(out.reason).toContain("denied by operator");
  });

  it("remembers always/never for the session, per tool", async () => {
    let calls = 0;
    const approver = createApprover({
      prompt: async () => {
        calls++;
        return "a";
      },
    });
    await approver.ask("files", "read_file", args);
    const second = await approver.ask("files", "read_file", args);
    expect(second.allowed).toBe(true);
    expect(second.reason).toContain("always");
    expect(calls).toBe(1); // no second prompt
    // a different tool still prompts
    const other = await approver.ask("files", "write_file", args);
    expect(other.allowed).toBe(true);
    expect(calls).toBe(2);

    const denier = createApprover({ prompt: async () => "x" });
    await denier.ask("files", "delete_file", args);
    const cached = await denier.ask("files", "delete_file", args);
    expect(cached.allowed).toBe(false);
    expect(cached.reason).toContain("never");
  });

  it("fails closed on timeout", async () => {
    const approver = createApprover({
      timeoutMs: 30,
      prompt: () => new Promise(() => {}), // never answers
    });
    const out = await approver.ask("files", "read_file", args);
    expect(out.allowed).toBe(false);
    expect(out.reason).toContain("timed out");
  });

  it("fails closed when there is no terminal", async () => {
    const approver = createApprover({ prompt: async () => null });
    const out = await approver.ask("files", "read_file", args);
    expect(out.allowed).toBe(false);
    expect(out.reason).toContain("no terminal");
  });

  it("fails closed on unrecognized input", async () => {
    const approver = createApprover({ prompt: async () => "huh?" });
    const out = await approver.ask("files", "read_file", args);
    expect(out.allowed).toBe(false);
  });

  it("shows args and the timeout in the prompt", async () => {
    let seen = "";
    const approver = createApprover({
      timeoutMs: 45000,
      prompt: async (text) => {
        seen = text;
        return "y";
      },
    });
    await approver.ask("files", "read_file", args);
    expect(seen).toContain("read_file");
    expect(seen).toContain("/safe/a.txt");
    expect(seen).toContain("45s");
    expect(seen).toContain("default deny");
  });
});
