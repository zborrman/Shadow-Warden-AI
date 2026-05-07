"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Eye, EyeOff } from "lucide-react";

export default function LoginPage() {
  const [key, setKey]       = useState("");
  const [error, setError]   = useState("");
  const [loading, setLoading] = useState(false);
  const [show, setShow]     = useState(false);
  const router = useRouter();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key }),
      });
      if (res.ok) {
        router.push("/");
        router.refresh();
      } else {
        setError("Invalid API key");
      }
    } catch {
      setError("Connection error — is the dashboard reachable?");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-surface-1 flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-3 mb-8 justify-center">
          <div className="p-2 rounded-xl bg-accent-purple/10 border border-accent-purple/20">
            <Shield size={24} className="text-accent-purple" />
          </div>
          <div>
            <p className="text-white font-semibold text-lg leading-tight">Shadow Warden</p>
            <p className="text-gray-500 text-xs">SOC Dashboard</p>
          </div>
        </div>

        <form onSubmit={submit} className="rounded-xl bg-surface-2 border border-border p-6 space-y-4">
          <h1 className="text-sm font-semibold text-white">Enter API Key</h1>
          <div className="relative">
            <input
              type={show ? "text" : "password"}
              value={key}
              onChange={e => setKey(e.target.value)}
              placeholder="warden_••••••••"
              autoFocus
              className="w-full px-3 py-2.5 pr-9 text-sm rounded-lg bg-surface-3 border border-border text-gray-200 placeholder-gray-600 focus:outline-none focus:border-accent-blue font-mono"
            />
            <button
              type="button"
              onClick={() => setShow(s => !s)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
              tabIndex={-1}
            >
              {show ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
          <button
            type="submit"
            disabled={!key || loading}
            className="w-full py-2.5 rounded-lg bg-violet-600 text-white text-sm font-medium hover:bg-violet-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? "Verifying…" : "Access Dashboard"}
          </button>
        </form>
        <p className="text-center text-xs text-gray-600 mt-4">Shadow Warden AI · SOC Operations Centre</p>
      </div>
    </div>
  );
}
