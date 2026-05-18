"use client";
import { useState } from "react";
import { Menu, X } from "lucide-react";
import { Sidebar } from "@/components/layout/sidebar";
import { ThemeProvider } from "@/components/ui/theme-provider";

export default function SocLayout({ children }: { children: React.ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <ThemeProvider>
      <div className="flex min-h-screen">
        {/* Mobile overlay */}
        {mobileOpen && (
          <div
            className="fixed inset-0 z-30 bg-black/60 md:hidden"
            onClick={() => setMobileOpen(false)}
          />
        )}

        {/* Sidebar — hidden on mobile unless mobileOpen */}
        <div className={[
          "fixed inset-y-0 left-0 z-40 md:static md:z-auto md:flex md:flex-col transition-transform duration-200",
          mobileOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0",
        ].join(" ")}>
          <Sidebar onClose={() => setMobileOpen(false)} />
        </div>

        {/* Main */}
        <main className="flex-1 min-w-0 bg-surface-0">
          {/* Mobile top bar */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-border md:hidden">
            <button
              onClick={() => setMobileOpen(true)}
              className="p-1.5 rounded-md text-gray-400 hover:text-white hover:bg-white/10 transition-colors"
              aria-label="Open sidebar"
            >
              <Menu size={18} />
            </button>
            <span className="text-sm font-semibold text-white">Shadow Warden</span>
          </div>
          {children}
        </main>
      </div>
    </ThemeProvider>
  );
}
