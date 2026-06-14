"use client";

import { statusColor } from "@/lib/utils";
import type { TimelineEntry } from "@/lib/types";

export function AgentTimeline({ entries }: { entries: TimelineEntry[] }) {
  return (
    <div className="glass rounded-xl p-6">
      <div className="space-y-0">
        {entries.map((entry, i) => (
          <div key={entry.id} className="relative pl-6">
            {i < entries.length - 1 && (
              <div className="absolute left-[7px] top-6 h-full w-px bg-slate-700" />
            )}
            <div
              className={`absolute left-0 top-1.5 h-3.5 w-3.5 rounded-full border-2 ${
                entry.severity === "critical"
                  ? "border-red-400 bg-red-500/30"
                  : entry.severity === "warning"
                    ? "border-amber-400 bg-amber-500/30"
                    : "border-cyan-400 bg-cyan-500/30"
              }`}
            />
            <div className="pb-6">
              <div className="flex items-baseline gap-3">
                <span className="font-mono text-xs text-slate-500">{entry.timestamp}</span>
                <span className={`text-sm font-semibold ${statusColor(entry.severity)}`}>{entry.type}</span>
              </div>
              <div className="mt-1 text-sm text-slate-300">{entry.detail}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
