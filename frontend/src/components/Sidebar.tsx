"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  Code2,
  FileText,
  Globe,
  LayoutDashboard,
  MessageSquare,
  Network,
  Shield,
  ShieldAlert,
} from "lucide-react";
import { clsx } from "clsx";
import { useDashboard } from "@/hooks/useDashboard";

const nav = [
  { href: "/chat", label: "Live Agent Chat", icon: MessageSquare },
  { href: "/integrate", label: "Integration", icon: Code2 },
  { href: "/dashboard", label: "Command Center", icon: LayoutDashboard },
  { href: "/graph", label: "Attack Graph", icon: Activity },
  { href: "/agent/travel", label: "Agent Timeline", icon: Shield },
  { href: "/network", label: "Network Security", icon: Network },
  { href: "/firewall", label: "Prompt Firewall", icon: ShieldAlert },
  { href: "/incidents", label: "Incidents", icon: FileText },
];

export function Sidebar() {
  const pathname = usePathname();
  const { connected } = useDashboard();

  return (
    <aside className="fixed left-0 top-0 z-40 flex h-screen w-56 flex-col border-r border-slate-800/80 bg-[#0d1117]/95 backdrop-blur-xl">
      <div className="flex items-center gap-2.5 border-b border-slate-800/80 px-5 py-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/20 ring-1 ring-cyan-500/40">
          <Globe className="h-4 w-4 text-cyan-400" />
        </div>
        <div>
          <div className="text-sm font-semibold tracking-tight text-white">SentinelAI</div>
          <div className="text-[10px] uppercase tracking-widest text-slate-500">WatchTower</div>
        </div>
      </div>

      <nav className="flex-1 space-y-0.5 p-3">
        {nav.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(href + "/");
          return (
            <Link
              key={href}
              href={href}
              className={clsx(
                "flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors",
                active
                  ? "bg-cyan-500/10 text-cyan-300 ring-1 ring-cyan-500/20"
                  : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200",
              )}
            >
              <Icon className="h-4 w-4 shrink-0" />
              {label}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-slate-800/80 p-4">
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <span className={clsx("h-2 w-2 rounded-full", connected ? "live-dot bg-emerald-400" : "bg-slate-600")} />
          {connected ? "Live stream connected" : "Connecting…"}
        </div>
      </div>
    </aside>
  );
}
