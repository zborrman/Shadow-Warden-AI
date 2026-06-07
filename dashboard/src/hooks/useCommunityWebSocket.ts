"use client";
import { useEffect, useState } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "https://api.shadow-warden-ai.com";
const WS_BASE = API_URL.replace(/^https/, "wss").replace(/^http(?!s)/, "ws");

export type WsStatus = "connecting" | "open" | "closed" | "error";

export interface CommunityLiveData {
  community_id:  string;
  member_count:  number;
  active_members?: number;
  file_count?:   number;
  compliance_score?: number;
  compliance_status?: string;
  last_activity?: string;
  [key: string]: unknown;
}

export function useCommunityWebSocket(communityId: string) {
  const [liveData, setLiveData]   = useState<CommunityLiveData | null>(null);
  const [wsStatus, setWsStatus]   = useState<WsStatus>("connecting");

  useEffect(() => {
    if (!communityId) return;

    let ws: WebSocket;
    let retryTimer: ReturnType<typeof setTimeout>;

    function connect() {
      ws = new WebSocket(`${WS_BASE}/ws/community/${communityId}`);

      ws.onopen    = () => setWsStatus("open");
      ws.onmessage = (e) => {
        try { setLiveData(JSON.parse(e.data as string) as CommunityLiveData); }
        catch { /* ignore non-JSON frames */ }
      };
      ws.onerror   = () => setWsStatus("error");
      ws.onclose   = (ev) => {
        setWsStatus("closed");
        if (!ev.wasClean) {
          retryTimer = setTimeout(connect, 30_000);
        }
      };
    }

    connect();
    return () => {
      clearTimeout(retryTimer);
      ws?.close(1000, "unmount");
    };
  }, [communityId]);

  return { liveData, wsStatus };
}
