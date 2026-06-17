"use client";
import * as React from "react";
import { cn } from "@/lib/utils";

interface TabsContextValue { active: string; setActive: (id: string) => void; }
const TabsContext = React.createContext<TabsContextValue | null>(null);
const useTabs = () => {
  const ctx = React.useContext(TabsContext);
  if (!ctx) throw new Error("Tabs sub-components must be used inside <Tabs>");
  return ctx;
};

interface TabsProps {
  defaultValue: string; value?: string; onValueChange?: (v: string) => void;
  children: React.ReactNode; className?: string;
}
function Tabs({ defaultValue, value, onValueChange, children, className }: TabsProps) {
  const [internal, setInternal] = React.useState(defaultValue);
  const active = value ?? internal;
  const setActive = (v: string) => { setInternal(v); onValueChange?.(v); };
  return (
    <TabsContext.Provider value={{ active, setActive }}>
      <div className={cn("w-full", className)}>{children}</div>
    </TabsContext.Provider>
  );
}

const TabsList = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} role="tablist"
      className={cn("inline-flex items-center gap-1 rounded-lg bg-white/5 border border-white/8 p-1", className)}
      {...props} />
  ),
);
TabsList.displayName = "TabsList";

function TabsTrigger({ value, className, children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { value: string }) {
  const { active, setActive } = useTabs();
  const isActive = active === value;
  return (
    <button role="tab" aria-selected={isActive} onClick={() => setActive(value)}
      className={cn(
        "inline-flex items-center justify-center whitespace-nowrap rounded-md px-3 py-1.5 text-sm font-medium transition-all",
        "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-brand-500",
        "disabled:pointer-events-none disabled:opacity-50",
        isActive ? "bg-dark-600 text-white shadow-sm" : "text-slate-400 hover:text-slate-200",
        className,
      )}
      {...props}
    >
      {children}
    </button>
  );
}

function TabsContent({ value, className, children, ...props }: React.HTMLAttributes<HTMLDivElement> & { value: string }) {
  const { active } = useTabs();
  if (active !== value) return null;
  return <div role="tabpanel" className={cn("mt-4", className)} {...props}>{children}</div>;
}

export { Tabs, TabsList, TabsTrigger, TabsContent };
