import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";

interface StatCardProps {
  label: string;
  value: string | number;
  sub?: string;
  icon: LucideIcon;
  accent?: "purple" | "blue" | "green" | "red" | "yellow" | "cyan";
  trend?: { value: number; positive?: boolean };
}

const ACCENT_MAP = {
  purple: "bg-accent-purple/10 text-accent-purple border-accent-purple/20",
  blue:   "bg-accent-blue/10   text-accent-blue   border-accent-blue/20",
  green:  "bg-accent-green/10  text-accent-green  border-accent-green/20",
  red:    "bg-accent-red/10    text-accent-red    border-accent-red/20",
  yellow: "bg-accent-yellow/10 text-accent-yellow border-accent-yellow/20",
  cyan:   "bg-accent-cyan/10   text-accent-cyan   border-accent-cyan/20",
};

export function StatCard({ label, value, sub, icon: Icon, accent = "blue", trend }: StatCardProps) {
  return (
    <div className="rounded-xl bg-surface-2 border border-border p-5 flex flex-col gap-3 hover:border-accent-blue/30 transition-colors">
      <div className="flex items-center justify-between">
        <p className="text-xs text-gray-500 font-medium uppercase tracking-wider">{label}</p>
        <div className={cn("w-8 h-8 rounded-lg border flex items-center justify-center", ACCENT_MAP[accent])}>
          <Icon size={14} />
        </div>
      </div>
      <div>
        <p className="text-2xl font-bold text-white">{value}</p>
        {sub && <p className="text-xs text-gray-500 mt-0.5">{sub}</p>}
      </div>
      {trend && (
        <p className={cn("text-xs font-medium", trend.positive !== false ? "text-accent-green" : "text-accent-red")}>
          {trend.value > 0 ? "+" : ""}{trend.value}% vs last hour
        </p>
      )}
    </div>
  );
}
