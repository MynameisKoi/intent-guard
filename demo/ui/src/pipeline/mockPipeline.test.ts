import { describe, expect, it } from "vitest";
import { parseGithubRepoLabel, runMockPipeline } from "./mockPipeline";
import { PIPELINE_STAGE_IDS } from "./pipelineTypes";

describe("parseGithubRepoLabel", () => {
  it("parses https URLs", () => {
    expect(parseGithubRepoLabel("https://github.com/acme/my-agent-repo")).toBe("acme/my-agent-repo");
    expect(parseGithubRepoLabel("https://github.com/acme/my-agent-repo.git")).toBe("acme/my-agent-repo");
  });

  it("parses SSH-style URLs", () => {
    expect(parseGithubRepoLabel("git@github.com:acme/cool-agent.git")).toBe("acme/cool-agent");
  });

  it("returns fallback on invalid input", () => {
    expect(parseGithubRepoLabel("not-a-url")).toBe("unknown/repo");
  });
});

describe("runMockPipeline", () => {
  it("runs stages in order and completes with a scan id", async () => {
    const events: string[] = [];
    const { scanId } = await runMockPipeline(
      { kind: "github", url: "https://github.com/org/repo" },
      (e) => {
        if (e.type === "stage" && e.status === "start") events.push(`+${e.stage}`);
        if (e.type === "stage" && e.status === "end") events.push(`-${e.stage}`);
        if (e.type === "complete") events.push(`done:${e.scanId}`);
      },
      { logDelayMs: 0, stagePauseMs: 0 },
    );

    expect(scanId).toMatch(/^scan_[a-z0-9]+$/);
    for (const id of PIPELINE_STAGE_IDS) {
      expect(events).toContain(`+${id}`);
      expect(events).toContain(`-${id}`);
    }
    expect(events.some((x) => x.startsWith("done:"))).toBe(true);
  });

  it("includes upload-specific ingestion logs for skill files", async () => {
    const logs: string[] = [];
    await runMockPipeline(
      { kind: "skill", fileName: "skills/x.md", byteLength: 1200 },
      (e) => {
        if (e.type === "log" && e.stage === "ingestion") logs.push(e.message);
      },
      { logDelayMs: 0, stagePauseMs: 0 },
    );
    expect(logs.some((m) => m.includes("skills/x.md"))).toBe(true);
  });

  it("aborts when signal is already aborted", async () => {
    const ac = new AbortController();
    ac.abort();
    const log: { type: string }[] = [];
    await expect(
      runMockPipeline(
        { kind: "github", url: "https://github.com/a/b" },
        (e) => log.push(e),
        { logDelayMs: 0, stagePauseMs: 0, signal: ac.signal },
      ),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(log.some((e) => e.type === "aborted")).toBe(true);
  });
});
