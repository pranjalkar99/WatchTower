"use client";

import type { Incident, PromptAnalysis } from "@/lib/types";

export function PromptFirewall({ analysis }: { analysis: PromptAnalysis | null }) {
  if (!analysis || !analysis.prompt) {
    return (
      <div className="glass flex h-64 items-center justify-center rounded-xl">
        <p className="text-sm text-slate-500">No threats detected. Run the attack demo to see analysis.</p>
      </div>
    );
  }

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="glass rounded-xl p-5">
        <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">Prompt</h3>
        <pre className="whitespace-pre-wrap rounded-lg bg-slate-950/60 p-4 font-mono text-sm leading-relaxed text-red-200 ring-1 ring-red-500/20">
          {analysis.prompt}
        </pre>
      </div>
      <div className="glass rounded-xl p-5">
        <h3 className="mb-4 text-xs font-semibold uppercase tracking-wider text-slate-500">AI Analysis</h3>
        <dl className="space-y-4">
          <div>
            <dt className="text-xs text-slate-500">Threat</dt>
            <dd className="text-lg font-semibold text-red-300">{analysis.threat}</dd>
          </div>
          <div>
            <dt className="text-xs text-slate-500">Confidence</dt>
            <dd className="text-lg font-semibold text-white">{analysis.confidence}%</dd>
          </div>
          <div>
            <dt className="text-xs text-slate-500">Risk</dt>
            <dd className="text-lg font-semibold text-red-400">{analysis.risk}</dd>
          </div>
          <div>
            <dt className="text-xs text-slate-500">Techniques</dt>
            <dd className="mt-1 flex flex-wrap gap-2">
              {analysis.techniques.map((t) => (
                <span key={t} className="rounded-md bg-red-500/10 px-2.5 py-1 text-xs font-medium text-red-300 ring-1 ring-red-500/20">
                  {t}
                </span>
              ))}
            </dd>
          </div>
          {analysis.detection_layers && Object.keys(analysis.detection_layers).length > 0 && (
            <div>
              <dt className="text-xs text-slate-500">CASCADE layers</dt>
              <dd className="mt-2 space-y-1.5">
                {[
                  ["Pattern", analysis.detection_layers.regex],
                  ["Semantic", analysis.detection_layers.semantic],
                  ["Behavior", analysis.detection_layers.behavior],
                  ["LLM agent", analysis.detection_layers.llm_agent ?? analysis.detection_layers.llm_judge],
                  ["Fused", analysis.detection_layers.fused],
                ].map(([label, val]) =>
                  val != null && val !== undefined ? (
                    <div key={label as string} className="flex justify-between text-xs">
                      <span className="text-slate-500">{label}</span>
                      <span className="font-mono text-cyan-300">{String(val)}</span>
                    </div>
                  ) : null,
                )}
                {analysis.detection_layers.predicted_tools && (
                  <div className="text-xs text-slate-500">
                    Predicted tools:{" "}
                    <span className="text-slate-300">
                      {(analysis.detection_layers.predicted_tools as string[]).join(", ")}
                    </span>
                  </div>
                )}
              </dd>
            </div>
          )}
          {analysis.reasoning && (
            <div>
              <dt className="text-xs text-slate-500">Reasoning</dt>
              <dd className="text-sm text-slate-300">{analysis.reasoning}</dd>
            </div>
          )}
        </dl>
      </div>
    </div>
  );
}

export function IncidentReport({ incident }: { incident: Incident | null }) {
  if (!incident) {
    return (
      <div className="glass flex h-64 items-center justify-center rounded-xl">
        <p className="text-sm text-slate-500">No incidents recorded. Trigger the attack demo to generate a report.</p>
      </div>
    );
  }

  const fields = [
    ["Agent", incident.agent],
    ["Attack Type", incident.attack_type],
    ["Risk", incident.risk],
    ["Affected Resources", incident.affected_resources.join(", ")],
    ["Target", incident.target],
    ["Actions Taken", incident.actions_taken.join(" · ")],
  ];

  return (
    <div className="glass rounded-xl p-6">
      <div className="mb-6 flex items-start justify-between">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-red-400">Security Incident</div>
          <h2 className="mt-1 text-2xl font-bold text-white">INCIDENT #{incident.number}</h2>
          <p className="mt-1 text-xs text-slate-500">Generated at {incident.created_at}</p>
        </div>
        <button
          onClick={() => window.print()}
          className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-sm font-medium text-slate-200 transition hover:bg-slate-700"
        >
          Download PDF
        </button>
      </div>
      <dl className="grid gap-4 sm:grid-cols-2">
        {fields.map(([label, value]) => (
          <div key={label} className="rounded-lg bg-slate-950/40 p-4 ring-1 ring-slate-800">
            <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">{label}</dt>
            <dd className="mt-1 text-sm font-semibold text-white">{value}</dd>
          </div>
        ))}
      </dl>
      {incident.prompt && (
        <div className="mt-4 rounded-lg bg-slate-950/40 p-4 ring-1 ring-slate-800">
          <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">Attack Prompt</dt>
          <dd className="mt-2 font-mono text-sm text-red-200">{incident.prompt}</dd>
        </div>
      )}
    </div>
  );
}
