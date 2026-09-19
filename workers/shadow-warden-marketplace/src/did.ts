// did.ts — the DID derivation, byte-for-byte the same function as
// `warden/marketplace/agent.py::pubkey_to_agent_id`.
//
// It lives in its own module with no Worker bindings so it can be executed
// outside workerd and compared against the Python original. Two independent
// implementations of an identity function that disagree are worse than one:
// the same key would name two different agents, and a signature verified on
// one surface would not verify on the other.
//
// `warden/tests/test_marketplace_worker_identity.py` runs this file under node
// against `pubkey_to_agent_id()` over shared vectors. If you edit the algorithm
// here, that test fails until Python agrees.

const B62_ALPHA = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/** Decode standard base64 to bytes. Throws on anything that is not base64. */
export function b64ToBytes(b64: string): Uint8Array {
  // atob is available in workerd and in node >= 16.
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * sha256(pubkey_bytes) as a big-endian integer, rendered base-62 most
 * significant digit first, truncated to 32 chars and right-padded with "0".
 *
 * SHA-256 always yields at least 43 base-62 digits, so the padding branch is
 * unreachable in practice; it is kept because the Python side has it and this
 * function's whole purpose is to not differ from Python.
 */
export async function deriveDidFragment(pubkeyB64: string): Promise<string> {
  const raw = b64ToBytes(pubkeyB64);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));

  let n = 0n;
  for (const byte of digest) n = (n << 8n) | BigInt(byte);

  let fragment = "";
  while (n > 0n) {
    fragment = B62_ALPHA[Number(n % 62n)] + fragment;
    n /= 62n;
  }
  return fragment.slice(0, 32).padEnd(32, "0");
}

export async function pubkeyToDid(pubkeyB64: string): Promise<string> {
  return "did:shadow:" + (await deriveDidFragment(pubkeyB64));
}

/**
 * True when `did` is the one this public key produces.
 *
 * This is the property that makes a DID self-proving: `agent_id` is *derived
 * from* the key, so possession of the key is the identity claim. A DID accepted
 * from a request body carries no such proof — which is how the Worker allowed a
 * caller to register any identifier at all, including one already in use on the
 * FastAPI gateway.
 */
export async function didMatchesPubkey(did: string, pubkeyB64: string): Promise<boolean> {
  let expected: string;
  try {
    expected = await pubkeyToDid(pubkeyB64);
  } catch {
    return false;
  }
  if (expected.length !== did.length) return false;
  // Constant-time compare: this decides an identity claim.
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ did.charCodeAt(i);
  return diff === 0;
}
