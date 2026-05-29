"use client";

import { useState } from "react";

const WARDEN_URL = process.env.NEXT_PUBLIC_WARDEN_URL ?? "http://localhost:8001";
const API_KEY    = process.env.NEXT_PUBLIC_WARDEN_API_KEY ?? "";

interface SemanticModelSummary {
  id: string;
  name: string;
  source_table: string;
  description: string;
  metric_count: number;
  dimension_count: number;
}

interface QueryResult {
  sql: string;
  model_id: string;
  metrics: string[];
  dimensions: string[];
  generation_ms: number;
}

async function fetchModels(): Promise<SemanticModelSummary[]> {
  const res = await fetch(`${WARDEN_URL}/semantic-layer/models`, {
    headers: { "X-API-Key": API_KEY },
    cache: "no-store",
  });
  if (!res.ok) return [];
  return res.json();
}

export default function SemanticLayerPage() {
  const [models, setModels] = useState<SemanticModelSummary[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [intent, setIntent] = useState("");
  const [selectedModel, setSelectedModel] = useState("");
  const [result, setResult] = useState<QueryResult | null>(null);
  const [error, setError] = useState("");

  async function loadModels() {
    setLoading(true);
    setError("");
    try {
      const data = await fetchModels();
      setModels(data);
      if (data.length > 0) setSelectedModel(data[0].id);
    } catch {
      setError("Failed to load models — is the warden API running?");
    } finally {
      setLoading(false);
    }
  }

  async function runIntent() {
    if (!intent.trim() || !selectedModel) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch(`${WARDEN_URL}/semantic-layer/query/intent`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": API_KEY },
        body: JSON.stringify({ model_id: selectedModel, intent, limit: 1000 }),
      });
      if (res.status === 503) {
        setError("ANTHROPIC_API_KEY not configured — AI Query unavailable.");
        return;
      }
      if (res.status === 402 || res.status === 403) {
        setError("Pro+ plan required for AI Query.");
        return;
      }
      if (!res.ok) throw new Error(await res.text());
      setResult(await res.json());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Semantic Layer</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Headless BI — centralized metric contracts + deterministic SQL generation.
          </p>
        </div>
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1 rounded-full bg-green-500/10 text-green-400 border border-green-500/20">
          ✅ Shipped · v5.1 · Pro+
        </span>
      </div>

      {/* Stats strip */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Models", value: models ? String(models.length) : "—" },
          { label: "Total Metrics", value: models ? String(models.reduce((a, m) => a + m.metric_count, 0)) : "—" },
          { label: "Total Dimensions", value: models ? String(models.reduce((a, m) => a + m.dimension_count, 0)) : "—" },
        ].map(({ label, value }) => (
          <div key={label} className="rounded-xl border bg-card p-4">
            <p className="text-xs text-muted-foreground uppercase tracking-wider">{label}</p>
            <p className="text-3xl font-bold mt-1">{value}</p>
          </div>
        ))}
      </div>

      {/* Load models */}
      {models === null && (
        <button
          onClick={loadModels}
          disabled={loading}
          className="px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50"
        >
          {loading ? "Loading…" : "Load Models"}
        </button>
      )}

      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
          {error}
        </div>
      )}

      {/* Model list */}
      {models && models.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-base font-semibold">Registered Models</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {models.map((m) => (
              <div
                key={m.id}
                className="rounded-xl border bg-card p-4 hover:border-primary/40 transition-colors cursor-pointer"
                onClick={() => setSelectedModel(m.id)}
                style={{ outline: selectedModel === m.id ? "2px solid rgb(var(--primary))" : undefined }}
              >
                <p className="font-mono text-xs text-muted-foreground">{m.id}</p>
                <p className="font-semibold mt-0.5">{m.name}</p>
                <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{m.description}</p>
                <div className="flex gap-3 mt-3 text-xs text-muted-foreground">
                  <span>
                    <span className="text-blue-400 font-medium">{m.metric_count}</span> metrics
                  </span>
                  <span>
                    <span className="text-green-400 font-medium">{m.dimension_count}</span> dims
                  </span>
                  <span className="font-mono text-slate-500">{m.source_table}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AI Query */}
      {models && models.length > 0 && (
        <div className="rounded-xl border bg-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold">AI Query</h2>
            <span className="text-xs text-muted-foreground">Natural language → SQL · Pro+</span>
          </div>

          <div className="space-y-3">
            <select
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              className="w-full rounded-lg border bg-background px-3 py-2 text-sm"
            >
              {models.map((m) => (
                <option key={m.id} value={m.id}>{m.name}</option>
              ))}
            </select>

            <textarea
              value={intent}
              onChange={(e) => setIntent(e.target.value)}
              placeholder='e.g. "Show total blocked requests by tenant for the last 7 days"'
              rows={3}
              className="w-full rounded-lg border bg-background px-3 py-2 text-sm resize-none"
            />

            <button
              onClick={runIntent}
              disabled={loading || !intent.trim()}
              className="px-5 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50"
            >
              {loading ? "Generating…" : "Generate SQL"}
            </button>
          </div>

          {result && (
            <div className="space-y-2">
              <p className="text-xs text-muted-foreground">
                Generated in {result.generation_ms} ms
              </p>
              <pre className="rounded-lg bg-slate-950 text-slate-200 p-4 text-xs overflow-x-auto whitespace-pre-wrap">
                {result.sql}
              </pre>
              <p className="text-xs text-muted-foreground">
                Ready to run against PostgreSQL / TimescaleDB.
              </p>
            </div>
          )}
        </div>
      )}

      {/* Architecture */}
      <div className="rounded-xl border bg-card p-5">
        <h2 className="text-base font-semibold mb-3">Architecture</h2>
        <div className="text-sm text-muted-foreground space-y-2">
          <p>
            The Semantic Layer sits between your application and the database. It defines a
            centralized contract of <span className="text-blue-400">metrics</span> (aggregation
            expressions) and <span className="text-green-400">dimensions</span> (column mappings),
            with per-tenant access rules.
          </p>
          <pre className="rounded-lg bg-slate-950 text-slate-300 p-3 text-xs overflow-x-auto">
{`NL Intent → Claude Haiku → QueryObject
                              ↓
                    SemanticEngine.generate()
                              ↓
                    Deterministic SQL → PostgreSQL`}
          </pre>
          <p>
            See{" "}
            <a
              href="http://localhost:8501"
              target="_blank"
              rel="noreferrer"
              className="text-primary underline-offset-4 hover:underline"
            >
              Streamlit Analytics (:8501)
            </a>{" "}
            → <em>15 Semantic Layer</em> for a full interactive query builder.
          </p>
        </div>
      </div>
    </div>
  );
}
