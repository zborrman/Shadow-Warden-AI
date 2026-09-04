import { AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * SW-7. What a page shows when the API did not answer.
 *
 * Five pages used to substitute fabricated data here — twenty invented events,
 * a block rate, $1.42M of "Estimated Savings" — rendered identically to the
 * real thing. An operator staring at a dead gateway had no way to tell. Going
 * blank is the honest failure; this says why the panel is blank.
 */
export function DataUnavailable({
  what,
  className,
}: {
  what: string;
  className?: string;
}) {
  return (
    <div
      role="status"
      className={cn(
        "rounded-xl border border-accent-yellow/30 bg-accent-yellow/5 p-4",
        "flex items-start gap-3",
        className,
      )}
    >
      <AlertTriangle size={14} className="text-accent-yellow shrink-0 mt-0.5" />
      <div>
        <p className="text-xs font-semibold text-accent-yellow">{what} unavailable</p>
        <p className="text-[11px] text-gray-400 mt-0.5">
          The Warden API did not answer. Nothing is estimated in its place — an
          empty panel here means unknown, not zero.
        </p>
      </div>
    </div>
  );
}

/**
 * The counterpart: sample data shown only while the first request is in flight.
 * React Query keeps `isPlaceholderData` true for exactly that window, so the
 * page can dim what it is showing and label it, rather than letting a sample
 * read as a measurement.
 */
export function PlaceholderNotice({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "px-1.5 py-0.5 rounded bg-surface-3 border border-border",
        "text-[10px] font-mono text-gray-500",
        className,
      )}
    >
      sample — loading
    </span>
  );
}
