# План глубокой инженерной модернизации — Shadow Warden AI

> **Track A — Security Remediation (`SR-*`).** Canonical registry & cross-track ownership: [`docs/unified-modernization-roadmap.md`](docs/unified-modernization-roadmap.md). Use `SR-*` IDs in commits, never a bare "Phase N". Data-layer (SR-5) is led by Track B under DE-6 — see registry decision C2.

**Дата:** 2026-07-10 · **Основание:** `AUDIT_REPORT_2026-07-10.md` (≈70 находок) + анализ архитектуры
**Цель:** довести кодовую базу до стандартов топовых компаний (Stripe / Cloudflare / Datadog-уровень): безопасность по умолчанию, тестируемость, наблюдаемость, детерминированный SDLC.

> **Статус исполнения:** Фаза 0 (CRITICAL marketplace SQL) — ✅ **выполнено** в этой сессии (`warden/marketplace/api.py`: добавлена авторизация `require_api_key`, обязательный scoping, defence-in-depth против DDL/DML-смаглинга). Остальные фазы — расписаны ниже для последовательного исполнения. Каждый пункт помечается риском, объёмом и критериями приёмки.

---

## Принципы модернизации (North Star)

1. **Secure by default, fail-closed на границе доверия.** Fail-open допустим только внутри пайплайна детекции (чтобы не блокировать легитимный трафик) и всегда с audit-логом. Auth, admin, кредитные/платёжные пути — только fail-closed.
2. **Один источник истины.** Ни одной третьей копии `_conn`/DDL/SQL-генератора. Общие примитивы — в `warden/db/` и `warden/security/`.
3. **Тонкие хендлеры, толстые сервисы.** Ни одной функции > 80 строк в hot-path; пайплайн разбит на тестируемые стадии.
4. **Наблюдаемость без PII.** Структурные логи и трейсы обязательны, но проходят тот же content-never-log инвариант, что и `/filter`.
5. **Каждый инвариант — тест.** Документированное правило безопасности без теста считается нарушенным.
6. **Документация = код.** Всё, что описано в CLAUDE.md/MEMORY, обязано существовать в коде (напр., JIT lease) либо быть удалено из docs.

---

## Дорожная карта по фазам

| Фаза | Тема | Риск | Объём | Блокирует релиз |
|---|---|---|---|---|
| 0 | Критические дыры (SQL, auth) | Низкий | S | ✅ да |
| 1 | Authentication & authorization | Средний | M | ✅ да |
| 2 | SSRF / egress-контроль | Средний | M | ✅ да |
| 3 | Корректность рантайма (баги High) | Средний | M | ✅ да |
| 4 | Инварианты безопасности (STAFF/GDPR) | Средний | M | ✅ да |
| 5 | Устранение техдолга (DB-слой, god-функции) | Высокий | L | нет |
| 6 | Наблюдаемость + fail-open дисциплина | Низкий | M | нет |
| 7 | SDLC / supply chain / CI-жёсткость | Низкий | M | нет |
| 8 | Doc-vs-code reconciliation + JIT lease | Средний | M | нет |

---

## ФАЗА 0 — Критические дыры  ✅ (частично выполнено)

**0.1 ✅ marketplace `/analytics/query`** — добавлена `require_api_key`, обязательный `caller_agent_id`, отклонение мульти-стейтментов и DDL/DML-ключевых слов.
**0.2 (осталось) Заменить произвольный SQL на whitelisted-запросы.** Даже с auth+scoping сырой `SELECT` — антипаттерн. Ввести реестр именованных параметризованных запросов (`_ALLOWED_ANALYTICS_QUERIES: dict[str, str]`); API принимает `query_name` + params, не сырой SQL. SOVA tool #32 и MCP переводятся на реестр.
- *Приёмка:* сырой SQL от клиента больше не достигает `con.execute`; 100% запросов параметризованы; тест на попытку чтения чужого агента → отказ.

---

## ФАЗА 1 — Authentication & Authorization

**1.1 Единый auth-контур.** Ввести ASGI-middleware, которое проставляет `request.state.auth` (tenant_id, tier, agent_id) ДО всех бизнес-зависимостей. `require_feature`/`require_plan` перестают читать сырой `X-Tenant-Tier` — тир берётся только из аутентифицированного контекста.
- *Файлы:* `warden/auth_guard.py`, `warden/billing/feature_gate.py:686-694`, `warden/main.py`.

**1.2 Закрыть роутеры без auth.** Добавить `Depends(require_api_key)` на: `/staff/*`, `/staff/agents/*` (`api/staff.py`, `staff_agents.py`), `/secrets/*` (`api/secrets.py`), `/agent/red-team/*` (`api/red_team.py`), `/document-intel/*` (`document_intel/api.py`), `/marketplace/*` (весь роутер, `marketplace/api.py`).
- *Правило:* публичными остаются только явно помеченные (`public_stats`, `discovery`, `saml`, `contact`) — с комментарием `# PUBLIC: <причина>`.
- *Защита от регресса:* при сбое импорта feature-gate НЕ `_GATE=[]`, а fail-closed (503).

**1.3 Admin-проверки → fail-closed + constant-time.** `api/kya.py:45-47`, `billing/router.py:57-60`: при пустом `ADMIN_KEY` → 503 (не открыто); сравнение через `hmac.compare_digest`. Вынести в общий `require_admin_key()` (один helper вместо N копий).

**1.4 IDOR-хардненинг.** Все эндпоинты, берущие `tenant_id` из тела/query, обязаны сверять его с `request.state.auth.tenant_id`. Ввести хелпер `assert_tenant(body.tenant_id, auth)`.

- *Приёмка Фазы 1:* автоматический тест-скан `warden/api/*.py` — каждый роут либо имеет auth-зависимость, либо в явном PUBLIC-allowlist; `X-Tenant-Tier` не влияет на доступ.

---

## ФАЗА 2 — SSRF / Egress-контроль

**2.1 Обязательный egress-guard.** Ввести единый `warden/security/egress.py::safe_get/safe_post`, который: (а) `assert_public_url` до резолва, (б) пиннинг валидированного IP, (в) `follow_redirects=False` либо ре-валидация каждого редиректа, (г) запрет private/link-local/metadata (`169.254.169.254`, `::1`, RFC1918).
**2.2 Перевести все user-controlled фетчи на guard:** `workers/probe_worker.py:40`, `communities/data_pod.py:294`, `communities/notifications.py:311,334`, `communities/federation.py:241`, `business_community/agentic_commerce/ucp.py`, `billing/usage_budgets.py:160`, `agent/tools.py:2329`.
**2.3 TOCTOU/DNS-rebind (`net_guard.py:100-116`):** guard возвращает валидированный IP, транспорт коннектится строго по нему (host-header pinning).
**2.4 CORS `/ext/*`:** заменить `ACAO: *` на allowlist origin'ов; не отражать произвольный Origin при наличии credential-заголовков.

- *Приёмка:* ни один исходящий HTTP из user-input не идёт мимо `egress.safe_*`; тест на `http://169.254.169.254/...` → блок.

---

## ФАЗА 3 — Корректность рантайма (High/Med баги)

**3.1 OpenAI-proxy URL (`openai_proxy.py:135` vs `841/911`).** Нормализация базового URL: единая функция строит `{base}/v1/...` для всех эндпоинтов, устраняя и пропуск `/v1`, и дублирование `/v1/v1`.
**3.2 Усечение стриминга при размаскировке (`openai_proxy.py:626-634`).** Не нарезать unmasked-текст по длинам masked-чанков. Вариант: отдавать размаскированный ответ отдельным финальным чанком, либо вести раздельные позиции masked/unmasked.
**3.3 Semantic Layer `_params` (`engine.py:601`).** `QueryResult` должен нести и SQL, и `params`; все потребители (`api.py:87,173`, `tools.py:518`, `semantic_budget.py:81`) передают params в исполнитель. Свести два SQL-генератора (`generate` vs `compile_query`) к одному.
**3.4 STIX-цепочка (`stix_audit.py:278-302`).** `UNIQUE(community_id, seq)` + retry на `IntegrityError` с ре-чтением вершины. Убирает форк цепочки при нескольких воркерах.
**3.5 Блокирующий I/O (`main.py:1552`, `logger.py:171`).** Все чтения `logs.json` в async — через `asyncio.to_thread`. Долгосрочно: перенести аналитику из NDJSON-файла в ClickHouse/SQLite-rollup.
**3.6 Детектор эскалации (`agent_monitor.py:706`).** Ловить и ступенчатую эскалацию: триггер при достижении destructive-тира независимо от `+1`.
**3.7 ZSET-коллизии (`velocity.py:76`, `transfer_guard.py:96`).** Уникальный суффикс члена: `f"{now:.6f}-{uuid4().hex[:8]}"`.
**3.8 Прочее:** None-guard `background_tasks` (`main.py:2203`); удержание ссылок `create_task` (реестр `_background_tasks`); LRU вместо `.clear()` (`logger.py:120`); health `degraded` при отказе Redis (`main.py:1436`); WalletShield сверка реальных токенов стрима (`openai_proxy.py:655`); zero-prior дрейф-гейт (`causal_arbiter.py:223`); удалить мёртвый `_collect_or_emit`.

- *Приёмка:* по каждому пункту — регрессионный тест, воспроизводящий баг до фикса.

---

## ФАЗА 4 — Инварианты безопасности

**4.1 `generate_sar()` (`compliance_kyc.py:197-238`)** — добавить `_prescreen_text()` на `suspicious_activity`/`transaction_details` (fail-open on timeout, как у соседних инструментов). Это прямое нарушение CLAUDE.md.
**4.2 A2A bypass (`a2a.py:207-211`)** — маршрутизировать выполнение через `staff_dispatch()` (или как минимум re-check `BoundaryRegistry` + suspension + VelocityGuard) перед `await handler(...)`. Сейчас приостановленный агент вызываем cross-agent.
**4.3 GDPR content-never-logged:** убрать `query_preview`/`final[:80]` (`structured_log.py:97`, `agents/base.py:116`); хешировать/убрать email из `auth_guard.py:244`; ввести sanitizer для `span.record_exception` (`telemetry.py:191`). Шифровать staff-SQLite тела тикетов/писем/SAR (Fernet), убрать `/tmp`-дефолт.
**4.4 Слабые ключи:** убрать хардкод-fallback `b"staff-intent-fallback"` (`boundaries.py:29`) — использовать `resolve_key()` как в `a2a.py`; при отсутствии ключа — fail-closed.
**4.5 Plaintext-секреты (`settings/service.py:250`)** — `create_secret()` шифрует значения Fernet (`VAULT_MASTER_KEY`) либо хранит metadata-only, как `vault_connector`.
**4.6 Синхронизировать статусы драфтов** (refund `PENDING_COUNTERSIGN`, SAR `DRAFT`) с документированными строками или обновить docs.

- *Приёмка:* контракт-тесты (расширить `test_contract_security.py`) на каждый инвариант; grep-тест «нет user-текста в лог-стримах».

---

## ФАЗА 5 — Техдолг: DB-слой и god-функции

**5.1 Единый DB-слой `warden/db/`.** Один контекст-менеджер `connection()` (sqlite/Turso), гарантированный `close()`, DDL — в централизованных `migrations/`, применяются один раз на старте, а не на каждый вызов. Убрать 62 копии `_conn`/`_db` и дубли DDL из `app_factory.py`.
- *Устраняет:* утечки соединений (#кк-9/10/17/18, #баг-3), повторный DDL, дрейф схем.
**5.2 Redis — синглтон-пул.** Один `redis.ConnectionPool` на процесс; убрать per-request клиенты (`settings/service.py:40`, `engine.py:51`, `quota_middleware.py:165`, `scheduler.py:545`).
**5.3 Декомпозиция god-функций.** `_run_filter_pipeline` (918 строк) → 9 явных стадий-объектов с единым интерфейсом `Stage.run(ctx)`; `lifespan()` (580 строк) → регистр инициализаторов; `openai_proxy` хендлер → сервисный класс.
**5.4 Убрать мёртвый код:** `OPTIONAL_ROUTERS` (`app_factory.py:284`), `_collect_or_emit`, неиспользуемые globals.
**5.5 `update_config` (`main.py:1656`)** — вынести из `os.environ`-мутаций в персистентный per-tenant конфиг-стор с audit-логом.

- *Приёмка:* `grep -c "sqlite3.connect"` в бизнес-коде → близко к 0 (только db-слой); coverage не падает; все тесты зелёные.

---

## ФАЗА 6 — Наблюдаемость и дисциплина fail-open

**6.1 Запрет немого `except: pass`.** ~150 блоков → либо `record_failopen(reason, exc)` с логом, либо узкий `except`. Ввести lint-правило/CI-скан на `except Exception:\n    pass` без последующего лога.
**6.2 Единый fail-open helper.** `record_failopen()` уже есть — применить консистентно в BI/compliance/scheduler (`business_intelligence/service.py`, `compliance/posture_service.py`).
**6.3 SLO-метрики fail-open.** Prometheus-счётчик `warden_failopen_total{module,reason}` — чтобы «тихая деградация» стала видимой на дашборде и алертах.
**6.4 WebSocket compliance (`compliance_report.py:1041`)** — либо реально подписаться на `compliance:events`, либо исправить docstring; убрать финальный немой `except`.

---

## ФАЗА 7 — SDLC / Supply chain / CI-жёсткость

**7.1 Security-гейты в CI (обязательные, не informational):**
- `bandit` (SAST для Python), `pip-audit`/`osv-scanner` (CVE зависимостей), `semgrep` с правилами на SSRF/SQLi/hardcoded-secrets, `gitleaks` (секреты в истории).
- SBOM (CycloneDX) на каждый релиз; pin зависимостей + Dependabot.
**7.2 Coverage-гейт вверх:** текущий floor 75% → поэтапно 85%, с обязательным покрытием security-путей (auth, egress, инварианты) на 100%.
**7.3 mutation-testing расширить** за пределы `secret_redactor`/`semantic_guard` на `auth_guard`, `causal_arbiter`, `x402_gate`.
**7.4 Pre-commit hooks:** ruff + mypy (strict на изменённых файлах) + gitleaks локально.
**7.5 Типизация:** сократить 231 `type: ignore` — включить `mypy --strict` на новых модулях, ratchet вниз.
**7.6 Нагрузочное/хаос-тестирование:** k6/locust на `/filter`; проверка деградации при отказе Redis/ClickHouse.

---

## ФАЗА 8 — Doc-vs-code reconciliation

**8.1 JIT lease (крупнейший разрыв).** Docs/MEMORY заявляют fail-CLOSED Hermes JIT credential lease (v7.7/FE-52) — **в коде отсутствует** (`warden/guards/`, `warden/core/` пусты). Решение (за владельцем):
- (a) **Реализовать** `warden/security/jit_lease.py`: выдача краткоживущего HMAC-подписанного одноразового лиза на секрет; 503 при отсутствии мастер-секрета (fail-CLOSED); секрет никогда не в ответе; single-use через Redis/SQLite. ИЛИ
- (b) **Удалить** заявления из CLAUDE.md/MEMORY, чтобы docs не вводили в заблуждение об уровне защиты.
**8.2 Аудит остальных «shipped»-заявлений** (GSAM downstream, SAC) на предмет реального наличия кода на ветке; синхронизировать статусы в ROADMAP/MEMORY.

---

## Порядок исполнения и оценка

| Приоритет | Фазы | Ориентир |
|---|---|---|
| Немедленно (блок релиза) | 0 ✅, 1, 2, 3.1–3.4, 4.1–4.2 | 1–2 недели |
| Ближайший спринт | 3.5–3.8, 4.3–4.6, 6 | 2–3 недели |
| Структурный | 5, 7 | 3–5 недель |
| Стратегический | 8, 7.5–7.6 | по решению |

**Метод исполнения каждого пункта:** ветка → фикс → регрессионный тест, воспроизводящий дефект → `ruff`+`mypy`+`pytest` зелёные → PR с описанием инварианта → security-review workflow. Никаких изменений в защищённые инварианты (`clearing.py` Decimal, 32 Playwright-ассерта, x402 fail-open, content-never-log) без явного решения.

---

## Что сделано в этой сессии

- ✅ Аудит (4 субагента) → `AUDIT_REPORT_2026-07-10.md`.
- ✅ **Фаза 0.1** — закрыта CRITICAL-дыра: `warden/marketplace/api.py::analytics_sql_query` теперь требует `require_api_key`, обязательный scoping по `caller_agent_id`, отклоняет мульти-стейтменты и DDL/DML. Синтаксис + ruff чистые.
- ✅ **Фаза 1.2** — добавлена `require_api_key` на роутеры: `/staff/*` (`api/staff.py`), `/staff/agents/*` (`api/staff_agents.py`), `/secrets/*` (`api/secrets.py`), `/agent/red-team/*` (`api/red_team.py`), `/document-intel/*` (`document_intel/api.py`). Auth добавлен на уровне `APIRouter(dependencies=[...])` — покрывает все эндпоинты роутера; feature-gate сохранён рядом (staff несёт 2 зависимости). Все модули импортируются, ruff чист.
- ✅ **Фаза 1.3** — admin-проверки fail-closed + constant-time: `api/kya.py::_require_admin` (был fail-open при пустом `ADMIN_KEY`) и `billing/router.py::_require_admin` теперь используют `hmac.compare_digest` и отклоняют при отсутствии ключа.
- ✅ **Фаза 2 (SSRF)** — существующий `warden/net_guard.assert_public_url` (fail-closed, DNS-rebind + metadata-защита) подключён ко всем незащищённым исходящим путям, `follow_redirects` выключен (закрыт redirect-bypass): `workers/probe_worker.py` (HIGH), `communities/data_pod.py`, `communities/notifications.py` (Slack+Teams), `communities/federation.py`, `billing/usage_budgets.py`, `business_community/agentic_commerce/ucp.py` (4 точки), `agent/tools.py` (SOVA tool #61). Поведенческая проверка: metadata (`169.254.169.254`) и private (`127.0.0.1`) блокируются. Все файлы импортируются, ruff чист.
- ✅ **Фаза 3 (частично)** — корректность рантайма:
  - 3.3 Semantic Layer: `QueryResult` получил поле `params`, `engine.generate()` его заполняет — SQL с `%s` больше не теряет значения фильтра (`semantic_layer/models.py`, `engine.py`).
  - 3.4 STIX-цепочка: `(community_id, seq)` теперь UNIQUE + retry-loop на `IntegrityError` — форк цепочки между воркерами исключён (`communities/stix_audit.py`).
  - 3.7 ZSET-коллизии: члены получили уникальный суффикс `uuid4().hex[:8]` — недосчёт burst при совпадении времени устранён (`staff/velocity.py`, `communities/transfer_guard.py`).
  - 3.8 None-guard для poison-alert `background_tasks` (`main.py`).
  - *Health `degraded` (1436) — пропущено как ложная находка:* реальный отказ Redis уже даёт `"degraded: <exc>"` → `overall=degraded`; статус `"unavailable"` — намеренно отключённый Redis (`memory://`), корректно `ok`.
- ✅ **Фаза 3 (продолжение)**:
  - 3.1 OpenAI-proxy URL: введён `_openai_v1_base()` — chat/models/embeddings идут по единому корректному пути; устранены и пропуск `/v1` (404 на дефолте `api.openai.com`), и двойной `/v1/v1` при base с версией. Проверено на 3 конфигурациях (`openai_proxy.py`).
  - 3.2 Усечение стриминга: в masking-ветке последний контентный чанк забирает остаток unmasked-текста — хвост больше не теряется при размаскировке. Self-test подтвердил сохранение полного текста (`openai_proxy.py`).
  - 3.5 Блокирующий I/O: `api_stats` (горячий путь) читает `logs.json` через `asyncio.to_thread` (`main.py`). *Остаток:* `read_by_request_id` в GDPR/XAI-хендлерах — низкочастотные admin-эндпоинты, отложено.
  - 3.6 Детектор эскалации: `_check_privilege_escalation` теперь ловит и ступенчатую read→write→destructive (не только пропуск тира) (`agent_monitor.py`).
- ✅ **Фаза 4 (частично)** — инварианты:
  - 4.1 `generate_sar()` теперь пре-скринит freetext (`suspicious_activity`+`transaction_details`) через `_prescreen_text()` (fail-open), закрыт прямой нарушенный инвариант CLAUDE.md (`staff/tools/compliance_kyc.py`).
  - 4.2 A2A boundary-bypass: `A2ARouter.route()` теперь enforce'ит boundary/suspension целевого агента (`check_and_dispatch`) перед dispatch — инструменты приостановленного агента больше не вызываемы cross-agent. Enforce только при зарегистрированном boundary → нет регресса для незарегистрированных целей. 61 тест (A2A + staff) зелёный (`staff/a2a.py`).
- ✅ **CI baseline зелёный** на коммите `0c5d2f87`: Tests 3.11/3.12 (4768 passed), Lint, marketplace-readiness. Два marketplace-теста обновлены под новый mandatory-scoping контракт.
  - 4.3 GDPR-гигиена логов: `AgentSpan` больше не пишет сырой запрос/ввод (`query_preview`→`query_chars`, `input_preview`→`input_chars`), `agents/base.py` — ответ LLM как `reply_chars=N`, `auth_guard.py` OIDC — `email_hash` вместо сырого email. Только метаданные (тип/длина/тайминг).
  - 4.4 Слабые ключи: `sign_refund_intent()` перешёл с хардкод-fallback `b"staff-intent-fallback"` на `resolve_key("STAFF_INTENT_KEY", ...)` — fail-closed в проде, как A2A. Удалён мёртвый `_INTENT_KEY`. 61 staff-тест зелёный.
  - 4.5 Plaintext-секреты Settings Hub: `create_secret()`/`update_secret()` теперь шифруют `value` Fernet-ключом из `VAULT_MASTER_KEY` (эфемерный fallback в dev/тестах) — в Redis/`_mem` больше не попадает plaintext. Добавлен `reveal_secret_value()` как единственный путь дешифровки. Round-trip + 221 тест (вкл. `test_settings.py`) зелёные.
- ⏭️ Осталось: Фаза 1 — **1.1 (auth-middleware — инвазивно, отдельным циклом на свежем контексте)**, 1.4 (IDOR). Фаза 2 — 2.3 (IP-пиннинг), 2.4 (CORS `/ext/*`). Фаза 3 — 3.5-остаток, 3.8-остаток. Фаза 4 — 4.2-velocity (доп.). Фазы 5–8.
