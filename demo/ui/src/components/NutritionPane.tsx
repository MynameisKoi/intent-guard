import type { SkillPreview } from "../types";

const toneClass: Record<string, string> = {
  neutral: "text-slate-200",
  bad: "text-ig-danger",
  warn: "text-ig-warn",
};

export function NutritionPane({ skill }: { skill: SkillPreview }) {
  const n = skill.nutrition;
  return (
    <div className="space-y-6">
      <section>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ig-muted">Skill intent summary</h3>
        <p className="text-sm leading-relaxed text-slate-200">{n.intentSummary}</p>
      </section>
      {n.sections.length > 0 && (
        <div className="space-y-4">
          {n.sections.map((s) => (
            <section key={s.title} className="rounded-lg border border-ig-border bg-ig-bg/40 p-4">
              <h4 className={`mb-2 text-sm font-semibold ${toneClass[s.tone] ?? "text-slate-200"}`}>{s.title}</h4>
              <ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">
                {s.items.map((item, i) => (
                  <li key={i}>{item}</li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
