"use client";

import { statusColor } from "@/lib/utils";
import type { NetworkRequest } from "@/lib/types";

export function NetworkTable({ requests }: { requests: NetworkRequest[] }) {
  return (
    <div className="glass overflow-hidden rounded-xl">
      <div className="border-b border-slate-800/80 px-4 py-3">
        <h3 className="text-sm font-semibold text-white">Outbound Requests</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-800/60 text-left text-xs uppercase tracking-wider text-slate-500">
              <th className="px-4 py-2.5 font-medium">Time</th>
              <th className="px-4 py-2.5 font-medium">Agent</th>
              <th className="px-4 py-2.5 font-medium">Destination</th>
              <th className="px-4 py-2.5 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {requests.map((r) => (
              <tr key={r.id} className="border-b border-slate-800/40 hover:bg-slate-800/30">
                <td className="px-4 py-2.5 font-mono text-slate-400">{r.timestamp}</td>
                <td className="px-4 py-2.5 text-slate-200">{r.agent}</td>
                <td className="px-4 py-2.5 font-mono text-slate-300">{r.destination}</td>
                <td className={`px-4 py-2.5 font-semibold uppercase ${statusColor(r.status)}`}>
                  {r.status}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function DnsPanels({
  allowed,
  suspicious,
}: {
  allowed: string[];
  suspicious: string[];
}) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <div className="glass rounded-xl p-4">
        <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-emerald-400">Allowed Domains</h4>
        <ul className="space-y-1.5">
          {allowed.map((d) => (
            <li key={d} className="flex items-center gap-2 font-mono text-sm text-slate-300">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
              {d}
            </li>
          ))}
        </ul>
      </div>
      <div className="glass rounded-xl p-4">
        <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-red-400">Suspicious</h4>
        <ul className="space-y-1.5">
          {suspicious.map((d) => (
            <li key={d} className="flex items-center gap-2 font-mono text-sm text-slate-300">
              <span className="h-1.5 w-1.5 rounded-full bg-red-400" />
              {d}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
