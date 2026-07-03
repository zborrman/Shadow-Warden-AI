"""
warden/services — orchestration layer (architecture Phase 2).

Services sit between the thin HTTP routers (``warden/api``) and the domain
packages. They orchestrate multi-stage flows (the /filter pipeline, evolution,
…) and read shared singletons from ``warden.runtime`` — they never import
``warden.main``. See docs/architecture.md.
"""
