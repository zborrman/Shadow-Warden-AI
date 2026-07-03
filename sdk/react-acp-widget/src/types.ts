export interface AcpConfig {
  /** Shadow Warden gateway URL, e.g. https://api.shadow-warden-ai.com */
  gatewayUrl: string;
  /** Agent DID (did:shadow:...) */
  agentDid: string;
  /** Merchant / service identifier */
  merchantId: string;
  /** Soft budget ceiling per month in USD */
  monthlyBudgetUsd: number;
  /** Hard ceiling per individual transaction in USD */
  maxTransactionUsd: number;
  /** Called when a mandate token is issued */
  onAuthorized?: (mandate: AcpMandate) => void;
  /** Called on authorization failure */
  onError?: (error: string) => void;
}

export interface AcpMandate {
  token_id: string;
  agent_id: string;
  merchant_id: string;
  max_amount: number;
  currency: string;
  use_limit: number;
  expires_at: string;
  issued_at: string;
  status: 'ACTIVE' | 'EXHAUSTED' | 'EXPIRED' | 'REVOKED';
}

export interface BudgetStatus {
  monthly_budget_usd: number;
  spent_mtd_usd: number;
  remaining_usd: number;
  decision: 'allowed' | 'require_approval' | 'blocked';
  utilization_pct: number;
}
