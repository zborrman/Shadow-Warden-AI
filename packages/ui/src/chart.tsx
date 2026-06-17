"use client";
import * as React from "react";
import {
  ResponsiveContainer,
  LineChart,
  AreaChart,
  BarChart,
  Line,
  Area,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  type TooltipProps,
} from "recharts";
import { cn } from "./lib/utils";

/* Brand palette used across all chart series */
export const CHART_COLORS = [
  "#3b82f6", // brand-500
  "#8b5cf6", // violet-500
  "#06b6d4", // cyan-500
  "#10b981", // emerald-500
  "#f59e0b", // amber-500
  "#ef4444", // red-500
];

/* Shared tooltip style (reads CSS vars so it works in both dark/light) */
function ChartTooltip({ active, payload, label }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-border bg-card px-3 py-2 text-xs shadow-lg">
      <p className="mb-1 font-medium text-foreground">{label}</p>
      {payload.map((p) => (
        <div key={p.dataKey as string} className="flex items-center gap-2 text-muted-foreground">
          <span className="h-2 w-2 rounded-full" style={{ background: p.color }} />
          <span>{p.name}:</span>
          <span className="font-medium text-foreground">{p.value}</span>
        </div>
      ))}
    </div>
  );
}

type ChartType = "line" | "area" | "bar";

interface SeriesConfig {
  key:    string;
  label?: string;
  color?: string;
}

interface ChartProps {
  data:      Record<string, unknown>[];
  series:    SeriesConfig[];
  xKey:      string;
  type?:     ChartType;
  height?:   number;
  className?: string;
  grid?:     boolean;
  legend?:   boolean;
  stacked?:  boolean;
}

export function Chart({
  data, series, xKey, type = "line", height = 280,
  className, grid = true, legend = false, stacked = false,
}: ChartProps) {
  const commonProps = {
    data,
    margin: { top: 4, right: 4, left: -20, bottom: 0 },
  };

  const axisProps = {
    tick:       { fontSize: 11, fill: "hsl(var(--muted-foreground))" },
    axisLine:   { stroke: "hsl(var(--border))" },
    tickLine:   false as const,
  };

  const renderSeries = () =>
    series.map((s, i) => {
      const color = s.color ?? CHART_COLORS[i % CHART_COLORS.length];
      const name  = s.label ?? s.key;
      if (type === "bar")
        return <Bar key={s.key} dataKey={s.key} name={name} fill={color} radius={[4, 4, 0, 0]} stackId={stacked ? "stack" : undefined} />;
      if (type === "area")
        return (
          <Area
            key={s.key} type="monotone" dataKey={s.key} name={name}
            stroke={color} fill={color} fillOpacity={0.12}
            strokeWidth={2} dot={false} stackId={stacked ? "stack" : undefined}
          />
        );
      return (
        <Line key={s.key} type="monotone" dataKey={s.key} name={name}
          stroke={color} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
      );
    });

  const Inner = type === "bar" ? BarChart : type === "area" ? AreaChart : LineChart;

  return (
    <div className={cn("w-full", className)}>
      <ResponsiveContainer width="100%" height={height}>
        <Inner {...commonProps}>
          {grid && <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />}
          <XAxis dataKey={xKey} {...axisProps} />
          <YAxis {...axisProps} />
          <Tooltip content={<ChartTooltip />} />
          {legend && <Legend wrapperStyle={{ fontSize: 11 }} />}
          {renderSeries()}
        </Inner>
      </ResponsiveContainer>
    </div>
  );
}
