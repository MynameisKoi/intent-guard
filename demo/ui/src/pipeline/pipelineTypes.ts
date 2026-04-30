/**
 * Mirrors the production pipeline described in the root README and product workflow.
 * Stages are simulated in the demo; no network calls.
 */
export const PIPELINE_STAGE_IDS = [
  "ingestion",
  "static_parse",
  "graph",
  "semantic",
  "aggregate",
  "display",
] as const;

export type PipelineStageId = (typeof PIPELINE_STAGE_IDS)[number];

export type PipelineInput =
  | { kind: "github"; url: string }
  | { kind: "skill"; fileName: string; byteLength: number };

export type PipelineEvent =
  | { type: "stage"; stage: PipelineStageId; status: "start" | "end" }
  | { type: "log"; message: string; stage: PipelineStageId }
  | { type: "complete"; scanId: string; elapsedMs: number }
  | { type: "aborted" };
