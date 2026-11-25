// The strong-password rules, shown live while the person types. The server
// (warden/auth/password_policy.py) applies the same rules and is the authority;
// warden/tests/test_portal_password_policy.py keeps the two lists in step.

export const MIN_LENGTH = 12
const MAX_BYTES = 72
const COMMON = [
  'password', 'passw0rd', 'qwerty', '123456', 'letmein', 'welcome',
  'iloveyou', 'admin', 'shadowwarden', 'warden', 'amazon',
]

export interface Rule { label: string; ok: boolean }

export function passwordRules(pw: string, email = ''): Rule[] {
  const low = pw.toLowerCase()
  const local = (email.split('@')[0] || '').toLowerCase()
  const personal = (local.length >= 3 && low.includes(local)) || COMMON.some(w => low.includes(w))
  return [
    { label: `${MIN_LENGTH}+ characters`, ok: pw.length >= MIN_LENGTH && new TextEncoder().encode(pw).length <= MAX_BYTES },
    { label: 'Upper-case letter', ok: /[A-Z]/.test(pw) },
    { label: 'Lower-case letter', ok: /[a-z]/.test(pw) },
    { label: 'A number', ok: /[0-9]/.test(pw) },
    { label: 'A symbol', ok: /[^A-Za-z0-9]/.test(pw) },
    { label: 'No email name or common word', ok: pw.length > 0 && !personal },
  ]
}

/** 0 = empty, 1 weak … 4 strong. Strong means every rule passes. */
export function passwordLevel(rules: Rule[], pw: string): 0 | 1 | 2 | 3 | 4 {
  if (!pw) return 0
  const passed = rules.filter(r => r.ok).length
  if (passed === rules.length) return 4
  if (passed >= 5) return 3
  if (passed >= 3) return 2
  return 1
}
