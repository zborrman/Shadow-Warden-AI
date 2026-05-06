import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { Verdict } from "./types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function verdictColor(v: Verdict) {
  return {
    ALLOW:  "text-accent-green",
    LOW:    "text-accent-cyan",
    MEDIUM: "text-accent-yellow",
    HIGH:   "text-accent-orange",
    BLOCK:  "text-accent-red",
  }[v] ?? "text-gray-400";
}

export function verdictBg(v: Verdict) {
  return {
    ALLOW:  "bg-accent-green/10 text-accent-green border-accent-green/30",
    LOW:    "bg-accent-cyan/10 text-accent-cyan border-accent-cyan/30",
    MEDIUM: "bg-accent-yellow/10 text-accent-yellow border-accent-yellow/30",
    HIGH:   "bg-accent-orange/10 text-accent-orange border-accent-orange/30",
    BLOCK:  "bg-accent-red/10 text-accent-red border-accent-red/30",
  }[v] ?? "bg-gray-800 text-gray-400 border-gray-700";
}

export function fmtMs(ms: number) {
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)}s` : `${ms.toFixed(1)}ms`;
}

export function fmtNum(n: number) {
  return new Intl.NumberFormat().format(n);
}

export function fmtUsd(n: number) {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(n);
}
