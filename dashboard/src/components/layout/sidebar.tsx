"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard, Shield, AlertTriangle, FlaskConical,
  Activity, GitBranch, Settings, ChevronRight, DollarSign,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV = [
  { group: "SOC",      items: [
    { href: "/overview", icon: LayoutDashboard, label: "Overview" },
    { href: "/events",   icon: Shield,           label: "Events" },
    { href: "/threats",  icon: AlertTriangle,    label: "Threats" },
    { href: "/sandbox",  icon: FlaskConical,     label: "Filter Sandbox" },
    { href: "/roi",      icon: DollarSign,       label: "Dollar Impact" },
  ]},
  { group: "Platform", items: [
    { href: "/platform/metrics", icon: Activity,   label: "Metrics" },
    { href: "/platform/traces",  icon: GitBranch,  label: "Traces" },
    { href: "/settings",         icon: Settings,   label: "Settings" },
  ]},
];

export function Sidebar() {
  const path = usePathname();

  return (
    <aside className="flex flex-col w-56 shrink-0 bg-surface-2 border-r border-border min-h-screen">
      {/* Logo */}
      <div className="flex items-center gap-2 px-4 py-5 border-b border-border">
        <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-accent-purple to-accent-blue flex items-center justify-center text-xs font-bold">
          SW
        </div>
        <span className="text-sm font-semibold text-white tracking-wide">Shadow Warden</span>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2 py-4 space-y-6 overflow-y-auto">
        {NAV.map(({ group, items }) => (
          <div key={group}>
            <p className="px-2 mb-1 text-[10px] uppercase tracking-widest text-gray-500 font-semibold">{group}</p>
            {items.map(({ href, icon: Icon, label }) => {
              const active = path === href || path.startsWith(href + "/");
              return (
                <Link
                  key={href}
                  href={href}
                  className={cn(
                    "flex items-center gap-2.5 px-2 py-2 rounded-lg text-sm transition-colors group",
                    active
                      ? "bg-accent-purple/15 text-white"
                      : "text-gray-400 hover:text-white hover:bg-surface-4"
                  )}
                >
                  <Icon size={15} className={active ? "text-accent-purple" : "text-gray-500 group-hover:text-gray-300"} />
                  {label}
                  {active && <ChevronRight size={12} className="ml-auto text-accent-purple" />}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-4 py-3 border-t border-border">
        <p className="text-[10px] text-gray-600">v4.19 · SOC Dashboard</p>
      </div>
    </aside>
  );
}
