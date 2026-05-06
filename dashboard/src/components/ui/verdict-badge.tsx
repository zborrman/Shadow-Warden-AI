import { cn, verdictBg } from "@/lib/utils";
import type { Verdict } from "@/lib/types";

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return (
    <span className={cn("inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-semibold border", verdictBg(verdict))}>
      {verdict}
    </span>
  );
}
