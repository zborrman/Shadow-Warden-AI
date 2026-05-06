"use client";
import { Bell, RefreshCw } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";

interface HeaderProps { title: string; subtitle?: string; }

export function Header({ title, subtitle }: HeaderProps) {
  const qc = useQueryClient();

  return (
    <header className="flex items-center justify-between px-6 py-4 border-b border-border bg-surface-1/60 backdrop-blur sticky top-0 z-10">
      <div>
        <h1 className="text-base font-semibold text-white">{title}</h1>
        {subtitle && <p className="text-xs text-gray-500 mt-0.5">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-2">
        <button
          onClick={() => qc.invalidateQueries()}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-surface-4 text-gray-400 hover:text-white transition-colors"
        >
          <RefreshCw size={12} /> Refresh
        </button>
        <button className="relative p-2 rounded-lg bg-surface-4 text-gray-400 hover:text-white transition-colors">
          <Bell size={14} />
          <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-accent-red" />
        </button>
        <div className="flex items-center gap-2 pl-2 border-l border-border">
          <div className="w-7 h-7 rounded-full bg-gradient-to-br from-accent-purple to-accent-blue flex items-center justify-center text-[10px] font-bold">
            SOC
          </div>
          <span className="text-xs text-gray-400">Analyst</span>
        </div>
      </div>
    </header>
  );
}
