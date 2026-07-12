# Аудит кодовой базы `warden/` — сводный отчёт

**Дата:** 2026-07-10 · **Ветка:** `fix/main-ci-ratchet` · **Режим:** read-only (в проекте ничего не изменено)
**Метод:** 4 параллельных субагента — качество кода, баги, уязвимости, security-инварианты.

> ⚠️ **Оговорка о верификации.** Во время работы двух субагентов (баги, инварианты) внешний safety-классификатор был недоступен, поэтому их выводы не прошли автоматическую пере-проверку. Все находки конкретны (`file:line` + сценарий), но перед исправлением каждую следует подтвердить чтением кода. Ничего в проекте не менялось.

---

## Сводка по критичности

| Критичность | Кол-во | Ключевое |
|---|---|---|
| CRITICAL | 1 | Открытый SQL-эндпоинт marketplace без авторизации |
| HIGH | ~9 | Отброшенные SQL-параметры, plaintext-секреты, сломанный OpenAI-proxy URL, усечение стриминга, нарушение инварианта SAR, обход auth через `X-Tenant-Tier` |
| MEDIUM | ~25 | SSRF (×8), утечки соединений, гонки данных, блокирующий I/O, обход детекторов |
| LOW | ~20 | Мёртвый код, слабое логирование, edge-case дрейф |

**Два системных паттерна:** (а) ~150 «немых» `except Exception: pass` без логирования; (б) ~62 копии boilerplate `_conn`/`_db` (sqlite-или-Turso) с расходящейся корректностью жизненного цикла.

---

## 1. КАЧЕСТВО КОДА

### HIGH
1. `warden/semantic_layer/engine.py:601` — `SemanticEngine.generate()` строит параметризованный WHERE, затем **отбрасывает `_params`**; в `QueryResult.sql` остаются голые `%s`, значения фильтра теряются. Затрагивает `api.py:87,173`, `tools.py:518`, `semantic_budget.py:81`. **Худший конкретный дефект: каждый фильтр Semantic Layer — no-op.**
2. `warden/staff/a2a.py:198-203` — `route()` подписывает токен `_sign()` и тут же проверяет `_verify()` в той же функции; ветка DENIED недостижима, «anti-injection» — security theater.
3. `warden/settings/service.py:250-272` — `create_secret()` хранит **значения секретов в plaintext** JSON в Redis/dict, вопреки vault/Fernet-паттерну проекта.
4. `warden/business_community/agentic_commerce/semantic_budget.py:60-88` — `_fetch_mtd_spend()` генерирует запрос `ai_spend`, но **не выполняет его** (placeholder `return 0.0`); плюс SQL-выражение `DATE_TRUNC(...)` передано как значение фильтра → строковый литерал, никогда не совпадёт.
5. `warden/main.py:1692-2610` — `_run_filter_pipeline` ~918 строк / 308 statements, 8 inline `except Exception`; security-критичный пайплайн не тестируем в изоляции.
6. `warden/main.py:432-1015` — `lifespan()` ~580 строк, переинициализирует **17 module globals** одной строкой (`:433`).

### MEDIUM
7. `warden/settings/service.py:40-50`, `engine.py:51-76` — новый Redis-клиент (свой пул, не закрывается) на **каждый** `_get`/`_set`.
8. `engine.py:570-622` vs `641-692` — два разошедшихся copy-paste SQL-генератора; `compile_query` через `_safe_ident` отвергает легитимные колонки вроде `DATE(created_at)`.
9. `warden/staff/economics.py:72-89` — Turso: ручной `__enter__()`, `__exit__` не вызывается → утечка; `except (ImportError, Exception)` — запутанный catch.
10. `warden/staff/economics.py:122-132,162-178` — `record()`/`get_report()` без `try/finally` → утечка sqlite при ошибке execute (повторено в `healer.py:73`, `scheduler.py:835`).
11. `warden/api/communities_v2.py:101-105` — регистрация owner-membership проглочена `except Exception: pass` → community без владельца, без следа.
12. `warden/api/bot_entity.py:348-358` — проверка отзыва JTI fail-open с немым `pass` при недоступности Redis (отозванные токены принимаются), без `log.warning`.
13. `warden/settings/service.py:195-203` — `get_settings_summary()` хардкодит `api_key_count:0, secret_count:0`.
14. `warden/settings/service.py:37,57-80` — `_mem` fallback: при сбое чтения Redis (немой `pass`) чтения молча возвращают дефолты, состояние расходится по воркерам.
15. `warden/app_factory.py:284-320` — `OPTIONAL_ROUTERS` (37 записей) — **мёртвый код**, нигде не используется; при подключении удвоил бы staff-роуты.
16. `warden/app_factory.py:120-279` — DDL-блоки скопированы из `economics.py`, `a2a.py`, `audit_chain.py`, `sep.py` — два источника истины на схему, уже дрейфуют.
17. `warden/agent/tools.py:2572,2640` — `httpx.AsyncClient(...)` создаётся inline и не закрывается.
18. `warden/agent/scheduler.py:545-551,595-612` — `aioredis.from_url()` на каждый cron-запуск, не закрывается, `except Exception: pass`.
19. `warden/business_intelligence/service.py:141-509` — ~15 `except Exception: pass`; BI-отчёты молча пустеют при любой ошибке БД.
20. `warden/api/compliance_report.py:1041-1059` — WebSocket docstring обещает подписку на `compliance:events`, но цикл только `sleep(30)`; финальный `except Exception: pass`.
21. `warden/main.py:1656-1673` — `update_config` мутирует `os.environ` + `global` → per-process, расходится по воркерам, без audit-лога.
22. `warden/openai_proxy.py:191,427` — обработчик 285 statements с вложенным `_stream_gen` 126 statements.
23. `warden/staff/a2a.py:247-253` — `_resolve_handler` игнорирует `target_agent_id`; защищает только `ALLOWED_ROUTES`.
24. **62 модуля** дублируют почти идентичные `_conn`/`_db` sqlite-или-Turso helpers — фиксы (напр. #10) применяются в одной копии.

### LOW
25. `warden/staff/a2a.py:65-75` vs `88-96` — дублированная ветка внутри одной функции.
26. `warden/app_factory.py:16-18` — docstring про «BaseException safety», код ловит `Exception`; «billing, billing» дубль.
27. `warden/communities/sep.py:161-165` — docstring описывает несуществующую ветку env-var.
28. `warden/agent/tools.py:769` — `__import__("datetime").datetime.utcnow()` — deprecated naive-UTC + хак.
29. `warden/auth/oidc_guard.py:219` — `global _domain_map_loaded` объявлен, не присваивается.
30. `warden/agent/healer.py:140-151` — recipe-cache глушит все исключения, маскирует порчу SQLite в self-healing.
31. `warden/main.py:3396,3631` — `ws_stream`/`ws_monitor_stream` 92/85 statements, дублируют broadcast-паттерн.
32. `warden/compliance/posture_service.py:224,244,397-454` — шесть вложенных немых `except: pass`, без debug-логов.

---

## 2. БАГИ (логические дефекты рантайма)

### HIGH
1. `warden/openai_proxy.py:135` vs `:841`/`:911` (`config.py:1594`) — **сломанный upstream URL**. `_resolve_upstream()` → `{_UPSTREAM}/chat/completions`, но `list_models`/`proxy_embeddings` → `/v1/models`, `/v1/embeddings`. При дефолте `OPENAI_UPSTREAM=https://api.openai.com` чат уходит на `/chat/completions` без `/v1` → 404/502. Оба пути одним значением не удовлетворить.
2. `warden/openai_proxy.py:626-634` — **усечение стриминга при маскировании**. `_emit=_full` (unmasked), но нарезается по длинам masked-чанков (`_len=len(_d["content"])`). Размаскировка удлиняет (`[EMAIL_1]`9→17), `sum(_len)<len(_emit)` → хвост ответа теряется.

### MEDIUM
3. `warden/communities/peering.py:64`, `stix_audit.py:69` (и `sep.py`) — `_get_conn()` открывает новое соединение, гоняет DDL на каждый вызов, не закрывает → исчерпание файловых дескрипторов.
4. `warden/communities/stix_audit.py:278-302` — гонка `seq`/`prev_hash`: `_last_hash()`+`INSERT` под in-process `RLock`; при нескольких воркерах — форк цепочки (нет `UNIQUE`), `verify_chain()` → «Chain broken».
5. `warden/main.py:1552`, `warden/analytics/logger.py:171` — блокирующее чтение всего `logs.json` в async-хендлере блокирует event loop.
6. `warden/billing/quota_middleware.py:68-80,165` — tenant читается из `scope["state"]`, но auth — dependency, не middleware → падение в `"anonymous"`/спуфится `X-Tenant-ID`; плюс новый Redis-клиент на запрос.
7. `warden/agent_monitor.py:706` — `PRIVILEGE_ESCALATION` срабатывает только при пропуске тира (`cat > max_seen+1`); ступенчатая read→write→destructive не ловится.
8. `warden/staff/velocity.py:76,107`, `transfer_guard.py:96,113` — член ZSET по timestamp; два вызова в одну микросекунду `ZADD` тот же member → перезапись → недосчёт burst.
9. `warden/main.py:2203` — `background_tasks.add_task` без None-guard; при `None` → `AttributeError`, проглочен outer `except` → poison-alert теряется.
10. `warden/openai_proxy.py:449-492` — мёртвый broken `_collect_or_emit` (`async def`, не вызывается).
11. `warden/main.py:1723,1725,2458,2838,2840,3838` — `asyncio.create_task` без удержания ссылки → риск GC + потеря исключений.
12. `warden/analytics/logger.py:120-121` — `_SEEN_REQUEST_IDS.clear()` целиком при 50k → ломает идемпотентность на границе.
13. `warden/main.py:1436` — Redis `unavailable` → overall `ok`; полный отказ Redis скрыт от health-проб.
14. `warden/openai_proxy.py:655-659` — WalletShield стриминг: `record_actual(actual=_estimated_tok, ...)` — реальный расход не сверяется, дрейф бюджета.
15. `warden/causal_arbiter.py:223` — `if old == 0: return True` обходит 25%-дрейф-гейт (латентная дыра anti-poisoning).

**Проверено и НЕ баг:** p99-индекс в `api_stats`; `topology_guard` digest; Lua token-bucket в `cache.py`.

---

## 3. УЯЗВИМОСТИ

> Глобального auth-middleware нет — авторизация пороутовая через `Depends(require_api_key)`. `require_feature()`/`require_plan()` — **тарифные гейты, не authN**: откатываются на спуфящийся заголовок `X-Tenant-Tier` (`feature_gate.py:686-694`).

### CRITICAL
1. `warden/marketplace/api.py:713-750` — `POST /marketplace/analytics/query` **без авторизации** выполняет любой `SELECT` по всей marketplace-SQLite. Confused-Deputy guard пропускается, если нет `caller_agent_id`. Единственная защита — `stmt.upper().startswith("SELECT")`. Неаутентифицированный `{"sql":"SELECT * FROM marketplace_credits"}` читает кредиты/x402-балансы/эскроу/KYA всех арендаторов.

### HIGH
2. `warden/marketplace/api.py` (весь роутер, `main.py:1326`) — ноль `require_api_key`; analytics/stats/query доступны неаутентифицированно.
3. `warden/workers/probe_worker.py:40-49` (+`api/monitor.py:64`) — **SSRF**: `MonitorCreate.url` фетчится с `follow_redirects=True`, без `net_guard` → скан внутренних хостов, `169.254.169.254`.

### MEDIUM
4. `warden/document_intel/api.py:28,31,47,94` — `/document-intel/convert*` защищён только `require_feature(...)` (спуф `X-Tenant-Tier: enterprise`) → неаутентифицированная загрузка в MarkItDown/OCR (DoS).
5. `warden/api/kya.py:45-47` — `_require_admin` fail-open при пустом `ADMIN_KEY` + `!=` (timing). Контраст: `community.py:222` использует `hmac.compare_digest`.
6. `warden/communities/data_pod.py:294-298` — SSRF: `probe_pod()` фетчит community-supplied endpoint, `follow_redirects=True`, без guard.
7. `warden/communities/notifications.py:311,334` — SSRF: `_send_slack`/`_send_teams` POST на `sub.target` без `assert_public_url`.
8. `warden/business_community/agentic_commerce/ucp.py:52-54,73-74,99,128` — SSRF: `discover_store`/`search_products`/`add_to_cart`/`checkout` фетчат caller-URL без guard.
9. `warden/communities/federation.py:241-247` — SSRF: `_push_to_peer()` POST на `peer_webhook_url` без guard.
10. `warden/agent/tools.py:2329-2332` — SSRF: SOVA-tool #61 фетчит полностью управляемый `catalog_url`.
11. `warden/billing/router.py:57-60` — admin-key `!=` вместо `hmac.compare_digest` (timing).

### LOW
12. `warden/billing/usage_budgets.py:160-174` — blind SSRF: alert POST на `notify_slack` без guard.
13. `warden/main.py:1064-1082` — CORS: `_ExtensionCORSMiddleware` отдаёт `ACAO: *` с `Authorization`/`X-API-Key` на `/ext/*` (без cookie-creds — влияние ограничено).
14. `warden/net_guard.py:100-116` (дизайн) — TOCTOU/DNS-rebind: guard резолвит и валидирует, коннект — отдельно; rebindable-хост проходит. Рекомендация: пиннинг валидированного IP.

**Проверено и НЕ уязвимо:** `semantic_layer/engine.py:592-692` (идентификаторы через `_safe`, значения параметризованы); `portal_router.py:595`, `monitor.py:130`, `marketplace/listing.py:528` (колонки из хардкод-словарей); `oidc_guard.py:303` (`verify_signature=False` — только peek issuer, далее JWKS); нет `pickle`/`yaml.load`/`eval`/`exec` на внешних данных; нет хардкод-секретов в `warden/`; JWT `algorithms=[HS256]`, ключ из `VAULT_MASTER_KEY`.

---

## 4. ПРОВЕРКА SECURITY-ИНВАРИАНТОВ (docs vs code)

### STAFF (`warden/staff/`)
- **DRIFT — bypass:** `A2ARouter.route()` (`a2a.py:207-211`) вызывает `await handler(...)` **без** `BoundaryRegistry`-проверки и VelocityGuard → инструменты **приостановленного** агента вызываемы cross-agent (только `ALLOWED_ROUTES`).
- **VIOLATED:** `generate_sar()` (`compliance_kyc.py:197-238`) **не вызывает** `_prescreen_text()` на freetext (`suspicious_activity`/`transaction_details`) — CLAUDE.md явно требует. (`generate_seo_content`/`score_kyc_profile`/`screen_sanctions_list` — OK.)
- **Caveat:** `issue_refund` HMAC-ключ откатывается на хардкод `b"staff-intent-fallback"` при пустом `VAULT_MASTER_KEY` (`boundaries.py:29,105`) — в отличие от `a2a.py`, где `resolve_key()`.
- **DRIFT (naming):** refund → `PENDING_COUNTERSIGN`, SAR → `DRAFT` (по сути human-gated, но не документированные строки статуса).
- **OK:** `resolve_ticket_kb` static `_KB`; `AgentRole(StrEnum)`; `BoundaryViolationError`; модели только в `_MODEL_BY_LEVEL`.

### GDPR content-never-logged
- **DRIFT:** `structured_log.py:97,105-112` — `AgentSpan` логирует `query_preview` (первые 80 симв. сырого запроса); `agents/base.py:116` логирует `final[:80]` ответа LLM → PII в лог-стриме `warden.staff`.
- **DRIFT:** `auth_guard.py:244` — `log.info("OIDC auth: email=%s ...")` пишет email (PII).
- `telemetry.py:191-193` — `span.record_exception(exc)` может вынести user-текст из строк исключений (allowlist — только соглашение).
- Staff-SQLite хранит тела тикетов/писем/SAR (`support.py`, `bdr.py`, `compliance_kyc.py`) незашифрованно в `/tmp` по умолчанию.
- **OK:** `analytics/logger.py:60-97` — metadata-only.

### Fail-closed auth
- **OK:** startup `RuntimeError` (`main.py:467-474`, `config.py:1836-1840`); `hmac.compare_digest` (`auth_guard.py:134,179`).
- **VIOLATED — роутеры без auth:** `/staff/*`, `/staff/agents/*` (только `require_feature`, спуфится `X-Tenant-Tier`; при сбое импорта гейта `_GATE=[]` → 0 защиты); `/secrets/*` (`secrets.py:16,59`); `/agent/red-team/*`. ~21 из 71 `api/*.py` без ссылки на auth-токен (часть легитимно публична: `public_stats`, `discovery`, `saml`, `contact`).

### Fail-open / fail-closed направление
- **OK:** x402-гейт fail-open + `payment_bypassed` audit (`x402_gate.py:281-289`); injection pre-screen fail-open on timeout; Redis cache fail-open.
- **NOT FOUND — крупнейший doc-vs-code разрыв:** обещанного **fail-CLOSED JIT lease** (`hermes`/`jit_lease`) **нет в коде**. `warden/gsam/` — только ingest; `warden/guards/`, `warden/core/` — пустые `__init__`. Docs/MEMORY заявляют v7.7 JIT lease и что SAC (FE-52) его перестроил — ни того, ни другого на ветке нет.

### Атомарность / shadow ban / CPT / regex-гейт
- **OK:** `dynamic_rules.json` (`tempfile.mkstemp`+`os.replace`, `evolve.py:828`); `logs.json` append под lock + purge через `.tmp`+`os.replace`; shadow ban `secrets.choice()` (пул 93); CPT `max_drift=0.25` (`causal_arbiter.py:92,217`); `_validate_regex_safety()` вызывается (`evolve.py:363,511`).

### MasterAgent / x402 replay
- **OK (ceremonial):** `_verify_token()` перед каждым sub-agent (`master.py:286`), но токен выпускается и проверяется в одной функции — не пересекает границу доверия. Approval Redis 1h TTL — OK.
- **OK:** x402 replay — nonce+`issued_at` ±300s, `x402_used_nonces` PRIMARY KEY single-use; backward-compat без nonce и fail-open nonce-DB — намеренно, но ослабляют гарантии.

---

## Топ приоритетов (по риску)

1. **CRITICAL** — закрыть `POST /marketplace/analytics/query`: добавить `require_api_key` на весь marketplace-роутер; убрать произвольный SQL-эндпоинт.
2. **HIGH auth** — `require_api_key` на `/staff/*`, `/staff/agents/*`, `/secrets/*`, `/agent/red-team/*`; `X-Tenant-Tier` — не authN.
3. **HIGH SSRF** — все исходящие user-controlled фетчи (probe_worker, data_pod, notifications, ucp, federation, usage_budgets, SOVA #61) через `assert_public_url` с re-validation после редиректов.
4. **HIGH корректность** — `_params` в `SemanticEngine.generate()` (#кк-1); OpenAI-proxy URL (#баг-1); усечение стриминга (#баг-2).
5. **HIGH инвариант** — `_prescreen_text()` в `generate_sar()`; провести A2A через `staff_dispatch()` (boundary+velocity+suspension).
6. **Doc reconciliation** — JIT lease (fail-CLOSED) в коде отсутствует; статусы refund/SAR расходятся с docs; `query_preview`/OIDC-email нарушают content-never-logged.
7. **Crypto** — `kya.py`/`billing/router.py` admin-проверки → fail-closed + `hmac.compare_digest`; убрать хардкод-fallback `b"staff-intent-fallback"`.

---

## Присланное «руководство по исправлению» — оценка

Ваш `CLAUDE_INSTRUCTIONS.md` разбирает те же 15 багов + 4 инварианта и предлагает корректные направления фиксов. Замечания:
- Раздел 1 (маршрутизация на `gemini-2.0-flash`/`gpt-4o-mini`, формулы стоимости) — **не применимо**: проект по дизайну не отправляет данные третьим сторонам (GDPR-инвариант), маршрутизация моделей staff зафиксирована в `_MODEL_BY_LEVEL` (Haiku/Sonnet/Opus). Внедрять сторонние модели — нарушение архитектуры.
- Фиксы #1–#15 и 4 gap'а — по сути верны и совпадают с находками выше.
- Пункт про создание `warden/guards/jit_lease.py` — это **новая фича**, а не фикс; docs её обещают, кода нет. Решение (строить/убрать из docs) — за вами.

**Исправления не применялись — в проекте ничего не изменено.** Отчёт сохранён в `AUDIT_REPORT_2026-07-10.md`.
