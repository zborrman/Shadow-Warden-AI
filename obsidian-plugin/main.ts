import {
    App,
    Editor,
    ItemView,
    MarkdownView,
    Modal,
    Notice,
    Plugin,
    PluginSettingTab,
    Setting,
    TFile,
    WorkspaceLeaf,
    requestUrl,
    RequestUrlResponse,
} from "obsidian";

// ── Constants ─────────────────────────────────────────────────────────────────

const VIEW_TYPE_WARDEN = "warden-sidebar";
const DASHBOARD_NOTE    = "Warden Security Dashboard.md";

// ── Types ─────────────────────────────────────────────────────────────────────

interface WardenSettings {
    wardenUrl: string;
    apiKey: string;
    tenantId: string;
    communityId: string;
    autoScanOnSave: boolean;
    alertOnHigh: boolean;
    autoTagFrontmatter: boolean;
    localPrevalidation: boolean;
    showReputation: boolean;
    feedRefreshSec: number;
    scheduledScanEnabled: boolean;
    scheduledScanIntervalHours: number;
}

interface ScanResult {
    allowed: boolean;
    risk_level: string;
    secrets_found: string[];
    flags: string[];
    data_class: string;
    word_count: number;
    redacted_content: string;
    filename: string;
    scanned_at: string;
}

interface ShareResult {
    ueciid: string;
    community_id: string;
    display_name: string;
    data_class: string;
    filename: string;
    word_count: number;
    shared_at: string;
}

interface FeedEntry {
    ueciid: string;
    display_name: string;
    content_type: string;
    byte_size: number;
    shared_at: string;
}

interface ReputationResult {
    tenant_id: string;
    points: number;
    badge: string;
    entry_count: number;
    badge_emoji: string;
}

interface LocalHit {
    kind: string;
    count: number;
}

interface PublishQueueItem {
    content: string;
    filename: string;
    display_name: string;
    community_id: string;
    queued_at: string;
}

// Simplified XAI stage derived from scan result (no extra API call required)
interface PipelineStage {
    name: string;
    icon: string;
    verdict: "PASS" | "FLAG" | "BLOCK" | "SKIP";
    detail: string;
}

const DEFAULT_SETTINGS: WardenSettings = {
    wardenUrl:                  "http://localhost:8000",
    apiKey:                     "",
    tenantId:                   "default",
    communityId:                "",
    autoScanOnSave:             false,
    alertOnHigh:                true,
    autoTagFrontmatter:         true,
    localPrevalidation:         true,
    showReputation:             true,
    feedRefreshSec:             120,
    scheduledScanEnabled:       false,
    scheduledScanIntervalHours: 24,
};

// ── Local PII pre-validation ──────────────────────────────────────────────────

const LOCAL_PII_PATTERNS: [RegExp, string][] = [
    [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, "email"],
    [/\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/g, "phone"],
    [/\b\d{3}-\d{2}-\d{4}\b/g, "ssn"],
    [/\b4[0-9]{12}(?:[0-9]{3})?\b|\b5[1-5][0-9]{14}\b/g, "credit_card"],
    [/(?:sk-|ghp_|glpat-)[a-zA-Z0-9]{20,}/g, "api_key"],
    [/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g, "private_key"],
    [/(?:password|passwd|pwd)\s*[:=]\s*\S+/gi, "password"],
    [/(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["']?\S+["']?/gi, "secret"],
];

function localPrevalidate(content: string): LocalHit[] {
    const hits: LocalHit[] = [];
    for (const [pattern, kind] of LOCAL_PII_PATTERNS) {
        const matches = content.match(new RegExp(pattern.source, pattern.flags));
        if (matches?.length) hits.push({ kind, count: matches.length });
    }
    return hits;
}

// ── Pipeline XAI from scan result ────────────────────────────────────────────

function buildPipelineStages(r: ScanResult): PipelineStage[] {
    const hasSecret  = r.secrets_found.length > 0;
    const hasFlags   = r.flags.length > 0;
    const isHigh     = ["HIGH", "BLOCK"].includes(r.risk_level);
    const isClassified = r.data_class === "CLASSIFIED";

    return [
        {
            name:    "Secret Redactor",
            icon:    "🔐",
            verdict: hasSecret ? "FLAG" : "PASS",
            detail:  hasSecret ? r.secrets_found.slice(0, 2).join(", ") : "clean",
        },
        {
            name:    "Data Classification",
            icon:    "🗂",
            verdict: isClassified ? "BLOCK" : (["PII", "PHI"].includes(r.data_class) ? "FLAG" : "PASS"),
            detail:  r.data_class,
        },
        {
            name:    "Semantic Guard",
            icon:    "🧠",
            verdict: hasFlags ? (isHigh ? "BLOCK" : "FLAG") : "PASS",
            detail:  hasFlags ? r.flags.slice(0, 2).join(", ") : "no rules fired",
        },
        {
            name:    "Risk Decision",
            icon:    "⚖️",
            verdict: r.risk_level === "BLOCK" ? "BLOCK"
                   : r.risk_level === "HIGH"  ? "FLAG"
                   : "PASS",
            detail:  r.risk_level,
        },
    ];
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function riskClass(level: string): string {
    return `warden-badge warden-badge-${level.toLowerCase()}`;
}

function riskEmoji(level: string): string {
    return { ALLOW: "✅", LOW: "🟢", MEDIUM: "🟡", HIGH: "🔴", BLOCK: "🚨" }[level] ?? "⚠";
}

function badgeEmoji(badge: string): string {
    return { ELITE: "🏆", GUARDIAN: "🛡️", TOP_SHARER: "📡", CONTRIBUTOR: "⭐", NEWCOMER: "🌱" }[badge] ?? "🌱";
}

function verdictColor(v: PipelineStage["verdict"]): string {
    return { PASS: "#48bb78", FLAG: "#f6ad55", BLOCK: "#fc4444", SKIP: "#718096" }[v];
}

// ── Dataview dashboard content ────────────────────────────────────────────────

function buildDashboardNote(date: string): string {
    return `---
created: ${date}
warden_dashboard: true
---
# 🛡 Shadow Warden Security Dashboard

> Auto-generated by Shadow Warden AI — run "Create Security Dashboard" to refresh.
> Requires the [Dataview](https://github.com/blacksmithgu/obsidian-dataview) plugin.

---

## 🚨 High-Risk Notes

\`\`\`dataview
TABLE warden_risk AS "Risk", warden_data_class AS "Class", warden_flags AS "Flags", warden_scanned AS "Scanned"
FROM ""
WHERE (warden_risk = "HIGH" OR warden_risk = "BLOCK") AND warden_scanned
SORT warden_scanned DESC
\`\`\`

---

## 📋 All Scanned Notes

\`\`\`dataview
TABLE warden_risk AS "Risk", warden_data_class AS "Class", warden_scanned AS "Scanned"
FROM ""
WHERE warden_scanned
SORT warden_risk DESC, warden_scanned DESC
\`\`\`

---

## 🗂 Data Class Distribution

\`\`\`dataview
TABLE length(rows) AS "Count"
FROM ""
WHERE warden_data_class
GROUP BY warden_data_class
\`\`\`

---

## 🔐 Notes with Detected Secrets or Flags

\`\`\`dataview
TABLE warden_flags AS "Flags", warden_risk AS "Risk", warden_scanned AS "Scanned"
FROM ""
WHERE warden_flags AND length(warden_flags) > 0
SORT warden_scanned DESC
\`\`\`

---

## ✅ Clean Notes (ALLOW / LOW)

\`\`\`dataview
TABLE warden_data_class AS "Class", warden_scanned AS "Scanned"
FROM ""
WHERE (warden_risk = "ALLOW" OR warden_risk = "LOW") AND warden_scanned
SORT warden_scanned DESC
LIMIT 30
\`\`\`
`;
}

// ── Scan Result Modal ─────────────────────────────────────────────────────────

class ScanResultModal extends Modal {
    private result: ScanResult;
    private localHits: LocalHit[];

    constructor(app: App, result: ScanResult, localHits: LocalHit[] = []) {
        super(app);
        this.result = result;
        this.localHits = localHits;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.addClass("warden-modal");

        const r = this.result;
        const header = contentEl.createDiv("warden-modal-header");
        header.createEl("span", { text: "🛡 Shadow Warden — Scan Result" });
        header.createEl("span", { text: r.risk_level, cls: riskClass(r.risk_level) });

        contentEl.createEl("p", {
            text: r.allowed ? "✅ Safe to share" : "⚠ Review required before sharing",
        });

        if (this.localHits.length) {
            const loc = contentEl.createDiv("warden-section");
            loc.createDiv({ text: "⚡ Local pre-scan (instant)", cls: "warden-section-title" });
            const row = loc.createDiv();
            this.localHits.forEach(h =>
                row.createEl("span", { text: `${h.kind} (${h.count})`, cls: "warden-tag" })
            );
        }

        // Pipeline breakdown
        const pipe = contentEl.createDiv("warden-section");
        pipe.createDiv({ text: "Pipeline Stages", cls: "warden-section-title" });
        const stages = buildPipelineStages(r);
        stages.forEach(s => {
            const row = pipe.createDiv("warden-pipeline-row");
            row.createEl("span", { text: s.icon + " " + s.name, cls: "warden-pipeline-name" });
            const badge = row.createEl("span", { text: s.verdict });
            badge.style.cssText = `color:${verdictColor(s.verdict)};font-weight:700;font-size:0.78rem;`;
            row.createEl("span", { text: s.detail, cls: "warden-pipeline-detail" });
        });

        contentEl.createEl("hr", { cls: "warden-divider" });

        if (r.secrets_found.length) {
            const sec = contentEl.createDiv("warden-section");
            sec.createDiv({ text: `⚠ ${r.secrets_found.length} secret type(s) detected`, cls: "warden-section-title" });
            const tags = sec.createDiv();
            r.secrets_found.forEach(s => tags.createEl("span", { text: s, cls: "warden-tag" }));
        }

        if (r.flags.length) {
            const fl = contentEl.createDiv("warden-section");
            fl.createDiv({ text: "Flags", cls: "warden-section-title" });
            r.flags.forEach(f => fl.createEl("span", { text: f, cls: "warden-tag" }));
        }

        const meta = contentEl.createDiv("warden-section");
        meta.createDiv({ text: "Metadata", cls: "warden-section-title" });
        meta.createEl("p", { text: `Data class: ${r.data_class}` });
        meta.createEl("p", { text: `Words: ${r.word_count}` });
        meta.createEl("p", { text: `File: ${r.filename || "—"}` });

        if (r.secrets_found.length && r.redacted_content) {
            const red = contentEl.createDiv("warden-section");
            red.createDiv({ text: "Redacted version (safe to copy)", cls: "warden-section-title" });
            const pre = red.createEl("pre");
            pre.style.cssText = "max-height:200px;overflow:auto;font-size:0.78rem;";
            pre.createEl("code", { text: r.redacted_content.slice(0, 2000) });
        }
    }

    onClose() { this.contentEl.empty(); }
}

// ── Share Result Modal ────────────────────────────────────────────────────────

class ShareResultModal extends Modal {
    private result: ShareResult;

    constructor(app: App, result: ShareResult) {
        super(app);
        this.result = result;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.createEl("h3", { text: "🤝 Shared to Business Community" });
        contentEl.createEl("hr", { cls: "warden-divider" });
        const sec = contentEl.createDiv("warden-section");
        sec.createEl("p", { text: "UECIID", cls: "warden-section-title" });
        sec.createEl("code", { text: this.result.ueciid, cls: "warden-ueciid" });
        const info = contentEl.createDiv("warden-section");
        [
            ["Note", this.result.display_name],
            ["Community", this.result.community_id],
            ["Data class", this.result.data_class],
            ["Words", String(this.result.word_count)],
            ["Shared at", this.result.shared_at.slice(0, 19).replace("T", " ") + " UTC"],
        ].forEach(([label, value]) => {
            const row = info.createDiv();
            row.style.cssText = "display:flex;gap:12px;align-items:center;margin:4px 0;";
            row.createEl("span", { text: label, cls: "warden-section-title" });
            row.createEl("span", { text: value });
        });
    }

    onClose() { this.contentEl.empty(); }
}

// ── Community Feed Modal ──────────────────────────────────────────────────────

class FeedModal extends Modal {
    private entries: FeedEntry[];
    private communityId: string;

    constructor(app: App, entries: FeedEntry[], communityId: string) {
        super(app);
        this.entries = entries;
        this.communityId = communityId;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.createEl("h3", { text: `🤝 Community Feed — ${this.communityId}` });
        contentEl.createEl("p", {
            text: `${this.entries.length} note(s) shared in this community`,
            cls: "warden-section-title",
        });
        if (!this.entries.length) {
            contentEl.createEl("p", { text: "No notes shared yet." });
            return;
        }
        this.entries.forEach(e => {
            const card = contentEl.createDiv("warden-feed-entry");
            card.createEl("strong", { text: e.display_name || "Untitled" });
            const meta = card.createDiv("warden-feed-meta");
            meta.createEl("span", { text: e.shared_at?.slice(0, 10) || "—" });
            meta.createEl("span", { text: " · " });
            meta.createEl("span", { text: `${Math.round(e.byte_size / 1024 * 10) / 10} KB` });
            card.createEl("p", { text: e.ueciid, cls: "warden-ueciid" });
        });
    }

    onClose() { this.contentEl.empty(); }
}

// ── Sidebar View ──────────────────────────────────────────────────────────────

class WardenSidebarView extends ItemView {
    private plugin: WardenPlugin;
    private feedTimer: ReturnType<typeof setInterval> | null = null;
    private lastScanResult: ScanResult | null = null;
    private reputation: ReputationResult | null = null;

    constructor(leaf: WorkspaceLeaf, plugin: WardenPlugin) {
        super(leaf);
        this.plugin = plugin;
    }

    getViewType(): string { return VIEW_TYPE_WARDEN; }
    getDisplayText(): string { return "Warden"; }
    getIcon(): string { return "shield"; }

    async onOpen(): Promise<void> {
        this.registerEvent(
            this.app.workspace.on("active-leaf-change", () => this.renderScanStatus())
        );
        await this.render();
        this.startAutoRefresh();
    }

    async onClose(): Promise<void> {
        this.stopAutoRefresh();
    }

    private stopAutoRefresh(): void {
        if (this.feedTimer !== null) { clearInterval(this.feedTimer); this.feedTimer = null; }
    }

    private startAutoRefresh(): void {
        this.stopAutoRefresh();
        const sec = this.plugin.settings.feedRefreshSec;
        if (sec > 0) this.feedTimer = setInterval(() => this.refreshFeed(), sec * 1000);
    }

    async render(): Promise<void> {
        const root = this.containerEl.children[1] as HTMLElement;
        root.empty();
        root.addClass("warden-sidebar");

        // ── Header ─────────────────────────────────────────────────────────
        const header = root.createDiv("warden-sidebar-header");
        header.createEl("span", { text: "🛡 Shadow Warden", cls: "warden-sidebar-title" });
        const refreshBtn = header.createEl("button", { text: "↻", cls: "warden-sidebar-btn" });
        refreshBtn.title = "Refresh";
        refreshBtn.addEventListener("click", () => this.refreshFeed());

        // ── Reputation ──────────────────────────────────────────────────────
        if (this.plugin.settings.showReputation) {
            const repSection = root.createDiv("warden-sidebar-section");
            repSection.createEl("p", { text: "Reputation", cls: "warden-sidebar-label" });
            const repRow = repSection.createDiv("warden-reputation-row");
            repRow.id = "warden-rep-row";
            await this.renderReputation(repRow);
        }

        // ── Queue badge ─────────────────────────────────────────────────────
        const queueSection = root.createDiv("warden-sidebar-section");
        queueSection.id = "warden-queue-section";
        this.renderQueueBadge(queueSection);

        // ── Current note status + pipeline ──────────────────────────────────
        const scanSection = root.createDiv("warden-sidebar-section");
        scanSection.createEl("p", { text: "Current Note", cls: "warden-sidebar-label" });
        const scanDiv = scanSection.createDiv();
        scanDiv.id = "warden-scan-status";
        this.renderScanStatus(scanDiv);

        const scanBtn = scanSection.createEl("button", { text: "Scan now", cls: "warden-sidebar-btn warden-sidebar-btn-full" });
        scanBtn.addEventListener("click", () => this.plugin.scanCurrentNote());

        const dashBtn = scanSection.createEl("button", { text: "📊 Create Security Dashboard", cls: "warden-sidebar-btn warden-sidebar-btn-full" });
        dashBtn.addEventListener("click", () => this.plugin.createSecurityDashboard());

        // ── Community feed ──────────────────────────────────────────────────
        const feedSection = root.createDiv("warden-sidebar-section");
        feedSection.createDiv("warden-sidebar-section-header")
            .createEl("p", { text: "Community Feed", cls: "warden-sidebar-label" });
        const feedList = feedSection.createDiv("warden-sidebar-feed");
        feedList.id = "warden-sidebar-feed-list";
        await this.refreshFeed(feedList);
    }

    renderQueueBadge(container?: HTMLElement): void {
        const el = container ?? (this.containerEl.querySelector("#warden-queue-section") as HTMLElement | null);
        if (!el) return;
        el.empty();
        const q = this.plugin.publishQueue;
        if (!q.length) return; // hide section when empty
        const row = el.createDiv("warden-queue-row");
        row.createEl("span", { text: `📤 ${q.length} note(s) queued for publish`, cls: "warden-sidebar-muted" });
        const flushBtn = row.createEl("button", { text: "Flush", cls: "warden-sidebar-btn" });
        flushBtn.title = "Retry publishing queued notes now";
        flushBtn.addEventListener("click", async () => {
            await this.plugin.flushPublishQueue();
            this.renderQueueBadge();
        });
    }

    renderScanStatus(container?: HTMLElement): void {
        const el = container ?? (this.containerEl.querySelector("#warden-scan-status") as HTMLElement | null);
        if (!el) return;
        el.empty();

        const view = this.app.workspace.getActiveViewOfType(MarkdownView);
        if (!view) { el.createEl("p", { text: "No note open", cls: "warden-sidebar-muted" }); return; }

        const filename = view.file?.name ?? "Untitled";
        el.createEl("p", { text: filename, cls: "warden-sidebar-filename" });

        if (this.lastScanResult) {
            const r = this.lastScanResult;
            const row = el.createDiv("warden-sidebar-scan-row");
            row.createEl("span", { text: riskEmoji(r.risk_level) + " " + r.risk_level, cls: riskClass(r.risk_level) });
            row.createEl("span", { text: r.data_class, cls: "warden-sidebar-muted" });

            // Simplified pipeline visualization
            const pipe = el.createDiv("warden-pipeline-mini");
            buildPipelineStages(r).forEach(s => {
                const dot = pipe.createEl("span", { cls: "warden-pipeline-dot", title: `${s.name}: ${s.verdict} — ${s.detail}` });
                dot.style.background = verdictColor(s.verdict);
                dot.textContent = s.icon;
            });

            if (r.flags.length) {
                const flags = el.createDiv();
                r.flags.slice(0, 3).forEach(f => flags.createEl("span", { text: f, cls: "warden-tag" }));
            }
        } else {
            el.createEl("p", { text: "Not yet scanned", cls: "warden-sidebar-muted" });
        }
    }

    async refreshFeed(container?: HTMLElement): Promise<void> {
        const el = container ?? (this.containerEl.querySelector("#warden-sidebar-feed-list") as HTMLElement | null);
        if (!el) return;

        if (!this.plugin.settings.communityId) {
            el.empty();
            el.createEl("p", { text: "Set Community ID in settings.", cls: "warden-sidebar-muted" });
            return;
        }

        let entries: FeedEntry[] = [];
        try {
            const resp = await requestUrl({
                url: `${this.plugin.settings.wardenUrl}/obsidian/feed?community_id=${encodeURIComponent(this.plugin.settings.communityId)}&limit=10`,
                headers: this.plugin.publicHeaders(),
                throw: false,
            });
            if (resp.status === 200) entries = resp.json as FeedEntry[];
        } catch { /* fail-open */ }

        el.empty();
        if (!entries.length) { el.createEl("p", { text: "No entries yet.", cls: "warden-sidebar-muted" }); return; }

        entries.forEach(e => {
            const card = el.createDiv("warden-sidebar-feed-card");
            card.createEl("p", { text: e.display_name || "Untitled", cls: "warden-sidebar-feed-title" });
            const meta = card.createDiv("warden-sidebar-feed-meta");
            meta.createEl("span", { text: e.shared_at?.slice(0, 10) || "—" });
            meta.createEl("span", { text: " · " });
            meta.createEl("span", { text: e.ueciid, cls: "warden-ueciid-small" });
        });
    }

    async renderReputation(container: HTMLElement): Promise<void> {
        container.empty();
        try {
            const resp = await requestUrl({
                url: `${this.plugin.settings.wardenUrl}/obsidian/reputation`,
                headers: this.plugin.publicHeaders(),
                throw: false,
            });
            if (resp.status === 200) {
                const rep = resp.json as ReputationResult;
                this.reputation = rep;
                container.createEl("span", { text: `${badgeEmoji(rep.badge)} ${rep.badge}` });
                container.createEl("span", { text: ` ${rep.points} pts`, cls: "warden-sidebar-muted" });
                return;
            }
        } catch { /* fail-open */ }
        container.createEl("span", { text: "—", cls: "warden-sidebar-muted" });
    }

    updateScanResult(result: ScanResult): void {
        this.lastScanResult = result;
        this.renderScanStatus();
    }
}

// ── Main Plugin ───────────────────────────────────────────────────────────────

export default class WardenPlugin extends Plugin {
    settings: WardenSettings;
    publishQueue: PublishQueueItem[] = [];
    private statusBarEl: HTMLElement;
    private sidebarView: WardenSidebarView | null = null;
    private scheduleTimer: ReturnType<typeof setInterval> | null = null;

    async onload() {
        await this.loadSettings();
        await this.loadPersistentState();

        this.registerView(VIEW_TYPE_WARDEN, leaf => {
            this.sidebarView = new WardenSidebarView(leaf, this);
            return this.sidebarView;
        });

        // Status bar
        this.statusBarEl = this.addStatusBarItem();
        this.statusBarEl.addClass("warden-status-bar");
        this.statusBarEl.setText("🛡 Warden");
        this.statusBarEl.title = "Shadow Warden AI — click to scan current note";
        this.statusBarEl.addEventListener("click", () => this.scanCurrentNote());

        this.addRibbonIcon("shield", "Shadow Warden — Open sidebar", () => this.activateSidebar());

        // Commands
        this.addCommand({ id: "open-sidebar",              name: "Open Warden sidebar",                    callback: () => this.activateSidebar() });
        this.addCommand({ id: "scan-note",                 name: "Scan current note for secrets & PII",    editorCallback: (_: Editor) => this.scanCurrentNote() });
        this.addCommand({ id: "share-note",                name: "Share note to Business Community",        editorCallback: (_: Editor) => this.shareCurrentNote() });
        this.addCommand({ id: "scan-vault",                name: "Scan entire vault for secrets",           callback: () => this.scanVault() });
        this.addCommand({ id: "community-feed",            name: "View Business Community feed",            callback: () => this.viewFeed() });
        this.addCommand({ id: "update-frontmatter-tags",   name: "Update Warden tags in frontmatter",       callback: () => this.updateFrontmatterTags() });
        this.addCommand({ id: "create-security-dashboard", name: "Create Security Dashboard (Dataview)",    callback: () => this.createSecurityDashboard() });
        this.addCommand({ id: "flush-publish-queue",       name: "Flush offline publish queue",             callback: () => this.flushPublishQueue() });
        this.addCommand({ id: "check-connection",          name: "Check Warden connection",                 callback: () => this.checkConnection() });

        // Auto-scan on save
        if (this.settings.autoScanOnSave) {
            this.registerEvent(
                this.app.vault.on("modify", (file) => {
                    if (!(file instanceof TFile) || file.extension !== "md") return;
                    const view = this.app.workspace.getActiveViewOfType(MarkdownView);
                    if (view?.file === file) this.silentScan(file);
                })
            );
        }

        this.addSettingTab(new WardenSettingTab(this.app, this));

        this.app.workspace.onLayoutReady(() => {
            this.activateSidebar(false);
            this.startScheduledScan();
            // Flush queue on startup if items pending
            if (this.publishQueue.length) {
                setTimeout(() => this.flushPublishQueue(), 5000);
            }
        });
    }

    async onunload() {
        this.stopScheduledScan();
        this.app.workspace.detachLeavesOfType(VIEW_TYPE_WARDEN);
    }

    // ── Persistence ─────────────────────────────────────────────────────────

    private async loadPersistentState(): Promise<void> {
        const data = await this.loadData() ?? {};
        this.publishQueue = data.publishQueue ?? [];
    }

    private async savePersistentState(): Promise<void> {
        const data = await this.loadData() ?? {};
        data.publishQueue = this.publishQueue;
        await this.saveData(data);
    }

    // ── HTTP helpers ─────────────────────────────────────────────────────────

    publicHeaders(): Record<string, string> {
        const h: Record<string, string> = { "Content-Type": "application/json" };
        if (this.settings.apiKey)  h["X-API-Key"]   = this.settings.apiKey;
        if (this.settings.tenantId) h["X-Tenant-ID"] = this.settings.tenantId;
        return h;
    }

    private async post(path: string, body: unknown): Promise<RequestUrlResponse | null> {
        try {
            return await requestUrl({
                url: `${this.settings.wardenUrl}${path}`,
                method: "POST",
                headers: this.publicHeaders(),
                body: JSON.stringify(body),
                throw: false,
            });
        } catch (e) {
            new Notice(`Cannot reach Warden at ${this.settings.wardenUrl}: ${e}`);
            return null;
        }
    }

    private async get(path: string): Promise<RequestUrlResponse | null> {
        try {
            return await requestUrl({
                url: `${this.settings.wardenUrl}${path}`,
                method: "GET",
                headers: this.publicHeaders(),
                throw: false,
            });
        } catch (e) {
            new Notice(`Cannot reach Warden: ${e}`);
            return null;
        }
    }

    // ── Sidebar ──────────────────────────────────────────────────────────────

    async activateSidebar(reveal = true): Promise<void> {
        const existing = this.app.workspace.getLeavesOfType(VIEW_TYPE_WARDEN);
        if (existing.length && !reveal) return;
        if (!existing.length) {
            const leaf = this.app.workspace.getRightLeaf(false);
            if (!leaf) return;
            await leaf.setViewState({ type: VIEW_TYPE_WARDEN, active: true });
        }
        if (reveal) this.app.workspace.revealLeaf(this.app.workspace.getLeavesOfType(VIEW_TYPE_WARDEN)[0]);
    }

    // ── Local pre-validation ─────────────────────────────────────────────────

    private localScan(content: string): LocalHit[] {
        return this.settings.localPrevalidation ? localPrevalidate(content) : [];
    }

    // ── Frontmatter ──────────────────────────────────────────────────────────

    private async tagFrontmatter(file: TFile, result: ScanResult): Promise<void> {
        if (!this.settings.autoTagFrontmatter) return;
        try {
            await (this.app.fileManager as any).processFrontMatter(file, (fm: Record<string, unknown>) => {
                fm["warden_data_class"] = result.data_class;
                fm["warden_risk"]       = result.risk_level;
                fm["warden_flags"]      = result.flags;
                fm["warden_scanned"]    = result.scanned_at?.slice(0, 10) ?? new Date().toISOString().slice(0, 10);
            });
        } catch { /* older Obsidian — skip silently */ }
    }

    async updateFrontmatterTags(): Promise<void> {
        const view = this.app.workspace.getActiveViewOfType(MarkdownView);
        if (!view?.file) { new Notice("Open a markdown note first."); return; }
        this.statusBarEl.setText("🛡 Scanning…");
        const resp = await this.post("/obsidian/scan", { content: view.editor.getValue(), filename: view.file.name });
        if (!resp || resp.status >= 400) { this.statusBarEl.setText("🛡 Error"); return; }
        const result: ScanResult = resp.json;
        await this.tagFrontmatter(view.file, result);
        this.statusBarEl.setText(`🛡 ${result.risk_level}`);
        new Notice(`✅ Warden tags updated: ${result.data_class} | ${result.risk_level}`);
    }

    // ── Dataview Dashboard ───────────────────────────────────────────────────

    async createSecurityDashboard(): Promise<void> {
        const date = new Date().toISOString().slice(0, 10);
        const content = buildDashboardNote(date);
        let file = this.app.vault.getAbstractFileByPath(DASHBOARD_NOTE);

        try {
            if (file instanceof TFile) {
                await this.app.vault.modify(file, content);
                new Notice("📊 Security Dashboard updated.");
            } else {
                file = await this.app.vault.create(DASHBOARD_NOTE, content);
                new Notice("📊 Security Dashboard created — open it to view Dataview queries.");
            }
            // Open the note
            const leaf = this.app.workspace.getLeaf(false);
            if (file instanceof TFile) await leaf.openFile(file);
        } catch (e) {
            new Notice(`Failed to create dashboard: ${e}`);
        }
    }

    // ── Offline publish queue ────────────────────────────────────────────────

    private async enqueueShare(item: PublishQueueItem): Promise<void> {
        this.publishQueue.push(item);
        await this.savePersistentState();
        this.sidebarView?.renderQueueBadge();
        new Notice(`📤 Queued "${item.display_name}" — will publish when online.`);
    }

    async flushPublishQueue(): Promise<void> {
        if (!this.publishQueue.length) { new Notice("Queue is empty."); return; }

        new Notice(`Flushing ${this.publishQueue.length} queued note(s)…`);
        const remaining: PublishQueueItem[] = [];
        let sent = 0;

        for (const item of this.publishQueue) {
            const resp = await this.post("/obsidian/share", {
                content:      item.content,
                filename:     item.filename,
                display_name: item.display_name,
                community_id: item.community_id,
            });
            if (resp && resp.status < 400) {
                sent++;
                new Notice(`✅ Published "${item.display_name}" → ${resp.json.ueciid}`);
            } else {
                remaining.push(item); // keep for retry
            }
        }

        this.publishQueue = remaining;
        await this.savePersistentState();
        this.sidebarView?.renderQueueBadge();

        if (!remaining.length) new Notice(`✅ All ${sent} note(s) published.`);
        else new Notice(`⚠ ${sent} published, ${remaining.length} still queued (server unreachable).`);
    }

    // ── Scheduled scan ───────────────────────────────────────────────────────

    private startScheduledScan(): void {
        this.stopScheduledScan();
        if (!this.settings.scheduledScanEnabled) return;
        const ms = this.settings.scheduledScanIntervalHours * 3_600_000;
        this.scheduleTimer = setInterval(() => {
            new Notice("⏰ Warden scheduled scan starting…");
            this.scanVault();
        }, ms);
    }

    private stopScheduledScan(): void {
        if (this.scheduleTimer !== null) { clearInterval(this.scheduleTimer); this.scheduleTimer = null; }
    }

    // ── Commands ─────────────────────────────────────────────────────────────

    async scanCurrentNote() {
        const view = this.app.workspace.getActiveViewOfType(MarkdownView);
        if (!view) { new Notice("Open a markdown note first."); return; }

        const content  = view.editor.getValue();
        const filename = view.file?.name ?? "";
        const localHits = this.localScan(content);

        if (localHits.length) {
            new Notice(`⚡ Local pre-scan: ${localHits.map(h => h.kind).join(", ")} detected — verifying…`, 3000);
        }

        this.statusBarEl.setText("🛡 Scanning…");
        const resp = await this.post("/obsidian/scan", { content, filename });
        if (!resp) { this.statusBarEl.setText("🛡 Error"); return; }
        if (resp.status >= 400) {
            new Notice(`Warden error ${resp.status}: ${resp.text.slice(0, 120)}`);
            this.statusBarEl.setText("🛡 Error");
            return;
        }

        const result: ScanResult = resp.json;
        this.statusBarEl.setText(`🛡 ${result.risk_level}`);
        this.sidebarView?.updateScanResult(result);
        if (view.file) await this.tagFrontmatter(view.file, result);
        new ScanResultModal(this.app, result, localHits).open();
    }

    async silentScan(file: TFile) {
        const content   = await this.app.vault.read(file);
        const localHits = this.localScan(content);
        const resp = await this.post("/obsidian/scan", { content, filename: file.name });
        if (!resp || resp.status >= 400) return;

        const result: ScanResult = resp.json;
        this.statusBarEl.setText(`🛡 ${result.risk_level}`);
        this.sidebarView?.updateScanResult(result);
        await this.tagFrontmatter(file, result);

        if (!result.allowed && this.settings.alertOnHigh) {
            new Notice(
                `⚠ Shadow Warden: ${result.risk_level} risk in "${file.name}"\n` +
                (result.secrets_found.length ? `Secrets: ${result.secrets_found.join(", ")}` : result.flags.join(", "))
            );
        }
        if (localHits.length && result.allowed) {
            new Notice(`⚡ Local pre-scan found ${localHits.map(h => h.kind).join(", ")} in "${file.name}" — verify manually.`, 5000);
        }
    }

    async shareCurrentNote() {
        if (!this.settings.communityId) {
            new Notice("Set a Community ID in Shadow Warden settings.");
            return;
        }
        const view = this.app.workspace.getActiveViewOfType(MarkdownView);
        if (!view) { new Notice("Open a markdown note first."); return; }

        const content     = view.editor.getValue();
        const filename    = view.file?.name ?? "Untitled.md";
        const displayName = filename.replace(/\.md$/i, "");
        const localHits   = this.localScan(content);

        if (localHits.length) {
            new Notice(`⚡ Local pre-scan detected: ${localHits.map(h => h.kind).join(", ")}\nServer will verify before sharing.`, 4000);
        }

        new Notice("Scanning before share…");
        const resp = await this.post("/obsidian/share", {
            content, filename,
            display_name: displayName,
            community_id: this.settings.communityId,
        });

        // Offline: enqueue and return
        if (!resp) {
            await this.enqueueShare({ content, filename, display_name: displayName, community_id: this.settings.communityId, queued_at: new Date().toISOString() });
            return;
        }
        if (resp.status === 400) { new Notice(`❌ Share blocked: ${resp.json?.detail ?? resp.text.slice(0, 120)}`); return; }
        if (resp.status >= 400)  { new Notice(`Warden error ${resp.status}`); return; }

        this.sidebarView?.refreshFeed();
        new ShareResultModal(this.app, resp.json).open();
    }

    async scanVault() {
        const files = this.app.vault.getMarkdownFiles();
        if (!files.length) { new Notice("No markdown files in vault."); return; }

        new Notice(`Scanning ${files.length} notes…`);
        let issues = 0;
        const flagged: string[] = [];

        for (const file of files) {
            const content = await this.app.vault.read(file);
            const resp = await this.post("/obsidian/scan", { content, filename: file.name });
            if (!resp || resp.status >= 400) continue;
            const result: ScanResult = resp.json;
            if (this.settings.autoTagFrontmatter) await this.tagFrontmatter(file, result);
            if (!result.allowed) { issues++; flagged.push(`${file.name} [${result.risk_level}]`); }
        }

        if (issues === 0) {
            new Notice(`✅ Vault clean — ${files.length} notes scanned, no issues found.`);
        } else {
            new Notice(`⚠ ${issues} note(s) need review:\n${flagged.slice(0, 5).join("\n")}${flagged.length > 5 ? `\n…and ${flagged.length - 5} more` : ""}`);
        }
    }

    async viewFeed() {
        if (!this.settings.communityId) { new Notice("Set a Community ID in settings."); return; }
        const resp = await this.get(`/obsidian/feed?community_id=${encodeURIComponent(this.settings.communityId)}&limit=50`);
        if (!resp) return;
        if (resp.status >= 400) { new Notice(`Feed error ${resp.status}`); return; }
        new FeedModal(this.app, resp.json as FeedEntry[], this.settings.communityId).open();
    }

    async checkConnection() {
        const resp = await this.get("/obsidian/stats");
        if (!resp) return;
        if (resp.status === 200) {
            const s = resp.json;
            new Notice(`✅ Connected to Shadow Warden v${s.version}\nTenant: ${s.tenant_id}`);
            this.statusBarEl.setText("🛡 Connected");
        } else {
            new Notice(`Connection failed: HTTP ${resp.status}`);
        }
    }

    // ── Settings ─────────────────────────────────────────────────────────────

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
    }

    async saveSettings() {
        await this.saveData(this.settings);
    }
}

// ── Settings Tab ──────────────────────────────────────────────────────────────

class WardenSettingTab extends PluginSettingTab {
    plugin: WardenPlugin;

    constructor(app: App, plugin: WardenPlugin) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display(): void {
        const { containerEl } = this;
        containerEl.empty();
        containerEl.createEl("h2", { text: "Shadow Warden AI" });
        containerEl.createEl("p", { text: "Business Community integration — scan, share, protect.", cls: "setting-item-description" });

        // Connection
        containerEl.createEl("h3", { text: "Connection" });
        new Setting(containerEl).setName("Warden URL").setDesc("Base URL (no trailing slash)")
            .addText(t => t.setPlaceholder("http://localhost:8000").setValue(this.plugin.settings.wardenUrl)
                .onChange(async v => { this.plugin.settings.wardenUrl = v.replace(/\/$/, ""); await this.plugin.saveSettings(); }));
        new Setting(containerEl).setName("API Key").setDesc("X-API-Key header (optional)")
            .addText(t => t.setPlaceholder("warden_prod_xxxx").setValue(this.plugin.settings.apiKey)
                .onChange(async v => { this.plugin.settings.apiKey = v; await this.plugin.saveSettings(); }));
        new Setting(containerEl).setName("Tenant ID").setDesc("X-Tenant-ID header")
            .addText(t => t.setPlaceholder("default").setValue(this.plugin.settings.tenantId)
                .onChange(async v => { this.plugin.settings.tenantId = v || "default"; await this.plugin.saveSettings(); }));

        // Community
        containerEl.createEl("h3", { text: "Business Community" });
        new Setting(containerEl).setName("Community ID").setDesc("ID for note sharing and feed")
            .addText(t => t.setPlaceholder("comm-xxxxxxxx").setValue(this.plugin.settings.communityId)
                .onChange(async v => { this.plugin.settings.communityId = v; await this.plugin.saveSettings(); }));
        new Setting(containerEl).setName("Feed refresh (seconds)").setDesc("Sidebar feed auto-refresh. 0 = manual only.")
            .addText(t => t.setPlaceholder("120").setValue(String(this.plugin.settings.feedRefreshSec))
                .onChange(async v => { this.plugin.settings.feedRefreshSec = parseInt(v) || 0; await this.plugin.saveSettings(); }));

        // Behaviour
        containerEl.createEl("h3", { text: "Behaviour" });
        new Setting(containerEl).setName("Auto-scan on save").setDesc("Silently scan on every modify (requires restart)")
            .addToggle(t => t.setValue(this.plugin.settings.autoScanOnSave)
                .onChange(async v => { this.plugin.settings.autoScanOnSave = v; await this.plugin.saveSettings(); }));
        new Setting(containerEl).setName("Alert on HIGH / BLOCK").setDesc("Show notice when auto-scan detects high risk")
            .addToggle(t => t.setValue(this.plugin.settings.alertOnHigh)
                .onChange(async v => { this.plugin.settings.alertOnHigh = v; await this.plugin.saveSettings(); }));
        new Setting(containerEl).setName("Auto-tag frontmatter").setDesc("Write warden_* YAML tags after each scan (enables Dataview dashboards)")
            .addToggle(t => t.setValue(this.plugin.settings.autoTagFrontmatter)
                .onChange(async v => { this.plugin.settings.autoTagFrontmatter = v; await this.plugin.saveSettings(); }));
        new Setting(containerEl).setName("Local PII pre-validation").setDesc("Run 8 regex patterns client-side before every server call")
            .addToggle(t => t.setValue(this.plugin.settings.localPrevalidation)
                .onChange(async v => { this.plugin.settings.localPrevalidation = v; await this.plugin.saveSettings(); }));
        new Setting(containerEl).setName("Show reputation in sidebar").setDesc("Display community badge and points")
            .addToggle(t => t.setValue(this.plugin.settings.showReputation)
                .onChange(async v => { this.plugin.settings.showReputation = v; await this.plugin.saveSettings(); }));

        // Scheduler
        containerEl.createEl("h3", { text: "Scheduled Scan" });
        new Setting(containerEl).setName("Enable scheduled vault scan").setDesc("Automatically scan the entire vault on a fixed interval")
            .addToggle(t => t.setValue(this.plugin.settings.scheduledScanEnabled)
                .onChange(async v => {
                    this.plugin.settings.scheduledScanEnabled = v;
                    await this.plugin.saveSettings();
                    if (v) this.plugin["startScheduledScan"](); else this.plugin["stopScheduledScan"]();
                }));
        new Setting(containerEl).setName("Scan interval (hours)").setDesc("How often the scheduled vault scan runs (min 1h)")
            .addText(t => t.setPlaceholder("24").setValue(String(this.plugin.settings.scheduledScanIntervalHours))
                .onChange(async v => {
                    this.plugin.settings.scheduledScanIntervalHours = Math.max(1, parseInt(v) || 24);
                    await this.plugin.saveSettings();
                    if (this.plugin.settings.scheduledScanEnabled) this.plugin["startScheduledScan"]();
                }));

        // Offline queue
        containerEl.createEl("h3", { text: "Offline Queue" });
        new Setting(containerEl)
            .setName(`Queued publishes: ${this.plugin.publishQueue.length}`)
            .setDesc("Notes queued while offline, waiting to be published")
            .addButton(b => b.setButtonText("Flush now").onClick(() => this.plugin.flushPublishQueue()));

        // Diagnostics
        containerEl.createEl("h3", { text: "Diagnostics" });
        new Setting(containerEl).setName("Test connection").setDesc("Verify Warden is reachable")
            .addButton(b => b.setButtonText("Check connection").setCta().onClick(() => this.plugin.checkConnection()));
        new Setting(containerEl).setName("Open sidebar").setDesc("Open the Warden community sidebar panel")
            .addButton(b => b.setButtonText("Open sidebar").onClick(() => this.plugin.activateSidebar()));
        new Setting(containerEl).setName("Security Dashboard").setDesc("Generate a Dataview dashboard note for all tagged files")
            .addButton(b => b.setButtonText("Create Dashboard").onClick(() => this.plugin.createSecurityDashboard()));
    }
}
