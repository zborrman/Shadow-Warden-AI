"""
warden/communities/
───────────────────
Business Communities — v2.8 cryptographic community layer.

Modules
───────
  id_generator  UUIDv7 + Snowflake ID for Community_ID / Member_ID / Entity_ID
  keypair       Ed25519 signing + X25519 encryption keypair per community; kid versioning
  key_archive   Fernet-wrapped key store + ROTATION_ONLY / ACTIVE / SHREDDED lifecycle
  rotation      ARQ background worker: CEK re-wrapping during Root Key Rollover
  break_glass   Emergency multi-sig access to archived keys (MCP tier only)
  clearance     Security Clearance Levels: PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED
  registry      Community + Member CRUD (PostgreSQL-backed)
  router        FastAPI router: /communities/* + /members/*
"""
