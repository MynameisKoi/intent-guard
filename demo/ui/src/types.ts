export type RiskLevel = "HIGH" | "MED" | "LOW";

export interface PreviewMeta {
  version: string;
  analysisProgress: number;
  highRiskCount: number;
  semanticStatus: string;
}

export interface SourceRef {
  id: string;
  label: string;
  kind: "github" | "mcp" | "upload";
}

export interface RiskCategory {
  id: string;
  label: string;
  level: "high" | "medium" | "low";
}

export interface Finding {
  id: string;
  title: string;
  body: string;
  owasp: string;
}

export interface NutritionSection {
  title: string;
  tone: "neutral" | "bad" | "warn";
  items: string[];
}

export interface GraphNode {
  id: string;
  label: string;
  kind: "function" | "datastore" | "flagged" | "external";
  x: number;
  y: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  variant: "normal" | "exfil";
  label?: string;
}

export interface OwaspCard {
  id: string;
  title: string;
  flagged: boolean;
}

export interface SkillPreview {
  id: string;
  name: string;
  risk: RiskLevel;
  language: string;
  lines: number;
  astDepth: number;
  scannedAgo: string;
  nutrition: {
    intentSummary: string;
    sections: NutritionSection[];
  };
  graph: null | {
    legend: { kind: GraphNode["kind"]; label: string }[];
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
  owasp: null | {
    cards: OwaspCard[];
    focusId: string;
    focusDetail: {
      title: string;
      risk: string;
      description: string;
      path: string;
    };
  };
  code: {
    lines: string[];
    highlights: { line: number; reason: string }[];
  };
}

export interface ScanPreview {
  meta: PreviewMeta;
  sources: SourceRef[];
  aggregate: {
    score: number;
    label: string;
    categories: RiskCategory[];
  };
  findings: Finding[];
  skills: SkillPreview[];
}
