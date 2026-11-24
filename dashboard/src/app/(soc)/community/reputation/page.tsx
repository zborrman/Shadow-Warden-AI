"use client";
import { LivePage, Panel, LiveTable, RecordsTable, Pill } from "@/components/ui/live";

// Thresholds mirror warden/communities/reputation.py::_badge_for.
const BADGES = [
  { badge: "NEWCOMER", threshold: "0 pts" },
  { badge: "CONTRIBUTOR", threshold: "25 pts" },
  { badge: "TOP_SHARER", threshold: "100 pts" },
  { badge: "GUARDIAN", threshold: "300 pts" },
  { badge: "ELITE", threshold: "750 pts" },
];

export default function ReputationPage() {
  return (
    <LivePage title="Reputation" subtitle="Community points, badges and the public leaderboard">
      <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
        <Panel title="Badges">
          <RecordsTable
            empty=""
            rows={BADGES}
            cols={[
              { key: "badge", label: "Badge", mono: true },
              { key: "threshold", label: "Threshold", mono: true },
            ]}
          />
        </Panel>
        <Panel title="Public leaderboard">
          <LiveTable
            what="Leaderboard"
            path="/public/leaderboard"
            listKeys={["leaderboard", "entries"]}
            empty="Nobody has earned points yet."
            cols={[
              { key: "rank", label: "Rank", mono: true },
              { key: "badge", label: "Badge", render: r => <Pill value={r.badge} tone="info" /> },
              { key: "entry_count", label: "Entries", mono: true },
              { key: "points", label: "Points", mono: true },
            ]}
          />
          <p className="text-[11px] text-gray-500 mt-3">
            The board shows rank, badge, entries and points — never a tenant ID.
          </p>
        </Panel>
      </div>
    </LivePage>
  );
}
