"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Users, ChevronDown, ChevronUp, Loader2 } from "lucide-react";
import { api, type CommunityFeedItem } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Props {
  flags:     string[];
  riskLevel: string;
}

const MITRE_LABEL: Record<string, string> = {
  jailbreak_attempt:  "T1059.007",
  prompt_injection:   "T1190",
  secret_leak:        "T1552",
  social_engineering: "T1566",
  data_exfiltration:  "T1055",
};

function derivedQuery(flags: string[]): string {
  if (flags.length === 0) return "threat incident";
  return flags
    .slice(0, 2)
    .join(" ")
    .replace(/_/g, " ");
}

export function CommunityRecommendations({ flags, riskLevel }: Props) {
  const [expanded, setExpanded] = useState(true);

  const query = derivedQuery(flags);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["community-recs", flags.join(","), riskLevel],
    queryFn:  () => api.communityLookup({ query, risk_level: riskLevel }),
    enabled:  flags.length > 0,
    retry:    false,
    staleTime: 5 * 60 * 1000,
  });

  const mitreTag = flags[0] ? (MITRE_LABEL[flags[0]] ?? null) : null;

  return (
    <div className="rounded-xl bg-surface-2 border border-border p-5">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="flex items-center justify-between w-full"
      >
        <div className="flex items-center gap-2">
          <Users size={14} className="text-accent-cyan" />
          <p className="text-sm font-semibold text-white">Community Recommendations</p>
          {data && data.total > 0 && (
            <span className="px-1.5 py-0.5 rounded bg-accent-cyan/10 border border-accent-cyan/30 text-[10px] font-mono text-accent-cyan">
              {data.total} reports
            </span>
          )}
        </div>
        {expanded ? <ChevronUp size={14} className="text-gray-500" /> : <ChevronDown size={14} className="text-gray-500" />}
      </button>

      {expanded && (
        <div className="mt-4 space-y-3">
          {/* MITRE tag */}
          {mitreTag && (
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase tracking-wider text-gray-600">MITRE ATT&CK</span>
              <span className="px-2 py-0.5 rounded bg-accent-purple/10 border border-accent-purple/30 text-xs font-mono text-accent-purple">
                {mitreTag}
              </span>
              <span className="text-xs text-gray-500">{flags[0]?.replace(/_/g, " ")}</span>
            </div>
          )}

          {isLoading ? (
            <div className="flex items-center gap-2 text-xs text-gray-500 py-2">
              <Loader2 size={12} className="animate-spin text-accent-cyan" />
              Querying community feed via SOVA…
            </div>
          ) : isError || !data ? (
            <p className="text-xs text-gray-600">Community data unavailable — SOVA API may be offline.</p>
          ) : (
            <>
              {/* Recommendations list */}
              {data.recommendations.length > 0 ? (
                <div className="space-y-2">
                  <p className="text-[10px] uppercase tracking-wider text-gray-600">
                    Recommendations · source: {data.source}
                  </p>
                  <ul className="space-y-1.5">
                    {data.recommendations.map((rec, i) => (
                      <li key={i} className="flex gap-2 text-xs text-gray-300">
                        <span className="text-accent-cyan shrink-0 font-mono">{i + 1}.</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="text-xs text-gray-600">
                  No specific recommendations for this flag type yet. MITRE fallback applied.
                </p>
              )}

              {/* Matched community entries */}
              {data.results.length > 0 && (
                <div className="space-y-1">
                  <p className="text-[10px] uppercase tracking-wider text-gray-600 mt-2">
                    Similar community reports ({data.results.length})
                  </p>
                  {data.results.slice(0, 3).map((item: CommunityFeedItem) => (
                    <div
                      key={item.ueciid}
                      className="flex items-center justify-between gap-2 py-1.5 border-b border-border/50 last:border-0"
                    >
                      <span className="text-xs text-gray-400 truncate flex-1">
                        {item.display_name}
                      </span>
                      <span className={cn(
                        "text-[10px] font-mono shrink-0",
                        item.risk_level === "HIGH" || item.risk_level === "CRITICAL"
                          ? "text-accent-red"
                          : "text-accent-yellow",
                      )}>
                        {item.risk_level}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
