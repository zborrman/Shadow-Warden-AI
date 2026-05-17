"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Users, Network, Key, Shield, LayoutDashboard, AlertTriangle,
  FlaskConical, Activity, GitBranch, Settings, DollarSign, LogOut,
  BookOpen, ChevronDown, ChevronRight, Cpu, Eye, Zap, Lock,
  Globe, FileText, TrendingUp, Search,
} from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

type NavItem = { href: string; icon: React.ElementType; label: string; soon?: true };
type NavGroup = {
  key: string;
  label: string;
  accent: string;
  bg: string;
  icon: React.ElementType;
  items: NavItem[];
};

const GROUPS: NavGroup[] = [
  {
    key: "community",
    label: "Business Community",
    accent: "#BF5AF2",
    bg: "rgba(191,90,242,0.12)",
    icon: Users,
    items: [
      { href: "/community",           icon: Users,    label: "Communities",      soon: true },
      { href: "/community/sep",       icon: Network,  label: "SEP Hub",          soon: true },
      { href: "/community/peering",   icon: Zap,      label: "Peering",          soon: true },
      { href: "/community/knock",     icon: Key,      label: "Knock Invitations",soon: true },
      { href: "/community/pods",      icon: Globe,    label: "Data Pods",        soon: true },
      { href: "/community/reputation",icon: TrendingUp,label: "Reputation",      soon: true },
    ],
  },
  {
    key: "security",
    label: "Cyber Security",
    accent: "#FF2D55",
    bg: "rgba(255,45,85,0.12)",
    icon: Shield,
    items: [
      { href: "/events",   icon: Shield,        label: "Filter Events" },
      { href: "/sandbox",  icon: FlaskConical,  label: "Filter Sandbox" },
      { href: "/threats",  icon: AlertTriangle, label: "Shadow AI",    soon: true },
      { href: "/xai",      icon: Eye,           label: "XAI Reports",  soon: true },
      { href: "/agents",   icon: Cpu,           label: "Agent Monitor",soon: true },
      { href: "/evolution",icon: Zap,           label: "Evolution Log", soon: true },
    ],
  },
  {
    key: "dashboard",
    label: "Dashboard",
    accent: "#0A84FF",
    bg: "rgba(10,132,255,0.12)",
    icon: LayoutDashboard,
    items: [
      { href: "/overview",         icon: LayoutDashboard, label: "Overview" },
      { href: "/events",           icon: FileText,        label: "Event Log" },
      { href: "/threats",          icon: Search,          label: "Threat Intel" },
      { href: "/platform/metrics", icon: Activity,        label: "Metrics" },
      { href: "/platform/traces",  icon: GitBranch,       label: "Traces" },
      { href: "/roi",              icon: DollarSign,      label: "Dollar Impact" },
    ],
  },
  {
    key: "settings",
    label: "Settings",
    accent: "#30D158",
    bg: "rgba(48,209,88,0.12)",
    icon: Settings,
    items: [
      { href: "/settings",            icon: Key,      label: "API Keys" },
      { href: "/settings/secrets",    icon: Lock,     label: "Secrets Vault",    soon: true },
      { href: "/settings/sovereign",  icon: Globe,    label: "Sovereign Routing",soon: true },
      { href: "/settings/gdpr",       icon: FileText, label: "GDPR Controls",   soon: true },
      { href: "/settings/billing",    icon: DollarSign,label: "Billing",         soon: true },
    ],
  },
];

const TOP_LINKS = [
  { href: "https://docs.shadow-warden-ai.com", icon: BookOpen, label: "Docs", accent: "#FFD60A", bg: "rgba(255,214,10,0.12)", external: true },
  { href: "/roi", icon: DollarSign, label: "Pricing", accent: "#FF8C42", bg: "rgba(255,140,66,0.12)", external: false },
];

function groupIsActive(group: NavGroup, path: string) {
  return group.items.some(i => !i.soon && (path === i.href || path.startsWith(i.href + "/")));
}

export function Sidebar() {
  const path = usePathname();
  const router = useRouter();

  const [open, setOpen] = useState<Record<string, boolean>>(() => {
    const initial: Record<string, boolean> = {};
    GROUPS.forEach(g => { initial[g.key] = groupIsActive(g, path ?? ""); });
    return initial;
  });

  async function signOut() {
    await fetch("/api/auth", { method: "DELETE" });
    router.push("/login");
    router.refresh();
  }

  function toggle(key: string) {
    setOpen(prev => ({ ...prev, [key]: !prev[key] }));
  }

  return (
    <aside className="flex flex-col w-60 shrink-0 bg-surface-2 border-r border-border min-h-screen">
      {/* Logo */}
      <div className="flex items-center gap-2 px-4 py-5 border-b border-border">
        <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-purple-500 to-blue-500 flex items-center justify-center text-xs font-bold text-white">
          SW
        </div>
        <span className="text-sm font-semibold text-white tracking-wide">Shadow Warden</span>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2 py-3 overflow-y-auto">

        {/* 4 collapsible groups */}
        {GROUPS.map(group => {
          const isOpen = open[group.key];
          const GroupIcon = group.icon;
          return (
            <div key={group.key} className="mb-0.5">
              {/* Group header */}
              <button
                onClick={() => toggle(group.key)}
                className="flex items-center gap-2 w-full px-2 py-2 rounded-lg text-[12px] font-semibold transition-colors hover:bg-white/5"
                style={{ color: isOpen ? group.accent : "#6b7280" }}
              >
                <GroupIcon size={13} style={{ color: isOpen ? group.accent : "#6b7280" }} />
                <span className="flex-1 text-left tracking-wide">{group.label}</span>
                {isOpen
                  ? <ChevronDown size={11} style={{ color: group.accent }} />
                  : <ChevronRight size={11} style={{ color: "#4b5563" }} />
                }
              </button>

              {/* Items */}
              {isOpen && (
                <div className="ml-3 border-l pl-2 py-0.5 space-y-0.5" style={{ borderColor: group.accent + "30" }}>
                  {group.items.map(item => {
                    const Icon = item.icon;
                    const active = !item.soon && (path === item.href || path.startsWith(item.href + "/"));
                    if (item.soon) {
                      return (
                        <div
                          key={item.href + item.label}
                          className="flex items-center gap-2 px-2 py-1.5 rounded-md text-[12px] opacity-35 cursor-not-allowed select-none"
                          style={{ color: "#6b7280" }}
                        >
                          <Icon size={13} />
                          <span>{item.label}</span>
                          <span className="ml-auto text-[9px] font-semibold tracking-widest opacity-70">SOON</span>
                        </div>
                      );
                    }
                    return (
                      <Link
                        key={item.href + item.label}
                        href={item.href}
                        className={cn(
                          "flex items-center gap-2 px-2 py-1.5 rounded-md text-[12px] transition-colors group",
                          active
                            ? "text-white"
                            : "text-gray-400 hover:text-white hover:bg-white/5"
                        )}
                        style={active ? { background: group.bg, color: group.accent } : {}}
                      >
                        <Icon size={13} style={active ? { color: group.accent } : {}} />
                        <span>{item.label}</span>
                      </Link>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}

        {/* Flat top-level links */}
        <div className="mt-2 pt-2 border-t border-border space-y-0.5">
          {TOP_LINKS.map(link => (
            <Link
              key={link.href}
              href={link.href}
              target={link.external ? "_blank" : undefined}
              rel={link.external ? "noopener noreferrer" : undefined}
              className="flex items-center gap-2 px-2 py-2 rounded-lg text-[12px] font-semibold transition-colors hover:bg-white/5"
              style={{ color: link.accent }}
            >
              <link.icon size={13} style={{ color: link.accent }} />
              <span>{link.label}</span>
              {link.external && (
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" className="ml-auto opacity-50">
                  <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6M15 3h6v6M10 14L21 3"/>
                </svg>
              )}
            </Link>
          ))}
        </div>
      </nav>

      {/* Footer */}
      <div className="px-4 py-3 border-t border-border space-y-2">
        <button
          onClick={signOut}
          className="flex items-center gap-2 w-full px-2 py-1.5 rounded-lg text-xs text-gray-500 hover:text-red-400 hover:bg-red-500/10 transition-colors"
        >
          <LogOut size={13} />
          Sign out
        </button>
        <p className="text-[10px] text-gray-600 px-2">v4.20 · SOC Dashboard</p>
      </div>
    </aside>
  );
}
