import type { SkillPreview } from "../types";

export function AnnotatedCode({ skill }: { skill: SkillPreview }) {
  const { lines, highlights } = skill.code;
  const highlightSet = new Map(highlights.map((h) => [h.line, h.reason]));

  return (
    <div className="overflow-hidden rounded-lg border border-ig-border bg-[#05070a] font-mono text-[13px] leading-relaxed">
      <div className="flex border-b border-ig-border bg-ig-panel px-3 py-2 text-[11px] text-ig-muted">
        <span className="text-ig-accent">{skill.language}</span>
        <span className="mx-2">·</span>
        <span>{lines.length} lines (preview)</span>
      </div>
      <pre className="overflow-x-auto p-4 text-slate-200">
        {lines.map((line, idx) => {
          const lineNo = idx + 1;
          const reason = highlightSet.get(lineNo);
          const flagged = Boolean(reason);
          return (
            <div
              key={lineNo}
              className={`flex gap-4 border-l-2 pl-2 ${flagged ? "border-ig-danger bg-red-950/35" : "border-transparent"}`}
            >
              <span className="w-8 shrink-0 select-none text-right text-slate-500">{lineNo}</span>
              <code className="whitespace-pre text-slate-100">{line}</code>
              {flagged && (
                <span className="ml-auto shrink-0 text-[11px] text-ig-danger">{reason}</span>
              )}
            </div>
          );
        })}
      </pre>
    </div>
  );
}
