/**
 * AcpWidget — Drop-in React component for Shadow Warden ACP budget authorization.
 *
 * Usage:
 *   <AcpWidget
 *     gatewayUrl="https://api.shadow-warden-ai.com"
 *     agentDid="did:shadow:ABC123..."
 *     merchantId="acme-corp"
 *     monthlyBudgetUsd={500}
 *     maxTransactionUsd={50}
 *     onAuthorized={(mandate) => setMandate(mandate)}
 *   />
 *
 * The widget displays current budget utilization and an Authorize button.
 * On click: POST /agentic/mandate → receive AcpMandate → call onAuthorized.
 */

import React, { useCallback, useEffect, useState } from 'react';
import type { AcpConfig, AcpMandate, BudgetStatus } from './types';

type Phase = 'idle' | 'loading' | 'authorized' | 'error';

interface Props extends AcpConfig {
  className?: string;
}

export function AcpWidget({
  gatewayUrl,
  agentDid,
  merchantId,
  monthlyBudgetUsd,
  maxTransactionUsd,
  onAuthorized,
  onError,
  className = '',
}: Props) {
  const [phase,  setPhase]  = useState<Phase>('idle');
  const [status, setStatus] = useState<BudgetStatus | null>(null);
  const [mandate, setMandate] = useState<AcpMandate | null>(null);
  const [err, setErr]       = useState<string>('');

  // Load budget status on mount
  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${gatewayUrl}/financial/budget/check`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            agent_id: agentDid,
            merchant_id: merchantId,
            monthly_budget_usd: monthlyBudgetUsd,
          }),
        });
        if (res.ok) {
          const data: BudgetStatus = await res.json();
          setStatus(data);
        }
      } catch {
        // Budget check is non-blocking
      }
    };
    void load();
  }, [gatewayUrl, agentDid, merchantId, monthlyBudgetUsd]);

  const handleAuthorize = useCallback(async () => {
    setPhase('loading');
    setErr('');
    try {
      const res = await fetch(`${gatewayUrl}/agentic/mandate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent_id:           agentDid,
          merchant_id:        merchantId,
          max_amount:         maxTransactionUsd,
          monthly_budget_usd: monthlyBudgetUsd,
          currency:           'USD',
          use_limit:          100,
        }),
      });

      if (!res.ok) {
        const detail = await res.text();
        throw new Error(`HTTP ${res.status}: ${detail}`);
      }

      const data: AcpMandate = await res.json();
      setMandate(data);
      setPhase('authorized');
      onAuthorized?.(data);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setErr(msg);
      setPhase('error');
      onError?.(msg);
    }
  }, [gatewayUrl, agentDid, merchantId, maxTransactionUsd, monthlyBudgetUsd, onAuthorized, onError]);

  const utilPct = status ? Math.round(status.utilization_pct) : 0;
  const barColor = utilPct >= 90 ? '#ef4444' : utilPct >= 70 ? '#f59e0b' : '#22c55e';

  return (
    <div
      className={className}
      style={{
        fontFamily: 'system-ui, sans-serif',
        border: '1px solid #e5e7eb',
        borderRadius: 8,
        padding: 16,
        maxWidth: 360,
        background: '#fff',
      }}
    >
      <div style={{ fontWeight: 600, marginBottom: 8, color: '#111827' }}>
        ACP Budget Authorization
      </div>

      {status && (
        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 12, color: '#6b7280', marginBottom: 4 }}>
            Monthly budget: ${status.spent_mtd_usd.toFixed(2)} / ${status.monthly_budget_usd.toFixed(2)} USD
          </div>
          <div style={{ background: '#f3f4f6', borderRadius: 4, height: 6, overflow: 'hidden' }}>
            <div style={{ width: `${Math.min(utilPct, 100)}%`, height: '100%', background: barColor, transition: 'width 0.3s' }} />
          </div>
          {status.decision === 'blocked' && (
            <div style={{ color: '#ef4444', fontSize: 12, marginTop: 4 }}>Budget exceeded — authorization blocked</div>
          )}
        </div>
      )}

      <div style={{ fontSize: 12, color: '#6b7280', marginBottom: 12 }}>
        Agent: <code style={{ fontSize: 11 }}>{agentDid.slice(0, 24)}…</code><br />
        Merchant: <strong>{merchantId}</strong><br />
        Max per tx: <strong>${maxTransactionUsd} USD</strong>
      </div>

      {phase === 'authorized' && mandate ? (
        <div style={{ padding: '8px 12px', background: '#f0fdf4', borderRadius: 6, fontSize: 12, color: '#166534' }}>
          ✓ Authorized — mandate <code>{mandate.token_id.slice(0, 16)}…</code><br />
          Expires: {new Date(mandate.expires_at).toLocaleString()}
        </div>
      ) : (
        <button
          onClick={() => { void handleAuthorize(); }}
          disabled={phase === 'loading' || status?.decision === 'blocked'}
          style={{
            width: '100%',
            padding: '8px 0',
            background: status?.decision === 'blocked' ? '#9ca3af' : '#2563eb',
            color: '#fff',
            border: 'none',
            borderRadius: 6,
            cursor: phase === 'loading' || status?.decision === 'blocked' ? 'not-allowed' : 'pointer',
            fontWeight: 500,
            fontSize: 14,
          }}
        >
          {phase === 'loading' ? 'Authorizing…' : 'Authorize Budget Mandate'}
        </button>
      )}

      {phase === 'error' && (
        <div style={{ marginTop: 8, color: '#ef4444', fontSize: 12 }}>Error: {err}</div>
      )}
    </div>
  );
}

export default AcpWidget;
