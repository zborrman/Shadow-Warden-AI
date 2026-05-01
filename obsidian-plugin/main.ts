import {
    App,
    Editor,
    MarkdownView,
    Modal,
    Notice,
    Plugin,
    PluginSettingTab,
    Setting,
    TFile,
    requestUrl,
    RequestUrlResponse,
} from "obsidian";

// ── Types ─────────────────────────────────────────────────────────────────────

interface WardenSettings {
    wardenUrl: string;
    apiKey: string;
    tenantId: string;
    communityId: string;
    autoScanOnSave: boolean;
    alertOnHigh: boolean;
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

const DEFAULT_SETTINGS: WardenSettings = {
    wardenUrl: "http://localhost:8000",
    apiKey: "",
    tenantId: "default",
    communityId: "",
    autoScanOnSave: false,
    alertOnHigh: true,
};

// ── Risk badge helper ─────────────────────────────────────────────────────────

function riskClass(level: string): string {
    return `warden-badge warden-badge-${level.toLowerCase()}`;
}

// ── Scan Result Modal ─────────────────────────────────────────────────────────

class ScanResultModal extends Modal {
    private result: ScanResult;

    constructor(app: App, result: ScanResult) {
        super(app);
        this.result = result;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.addClass("warden-modal");

        const r = this.result;

        // Header
        const header = contentEl.createDiv("warden-modal-header");
        header.createEl("span", { text: "🛡 Shadow Warden — Scan Result" });

        const badge = header.createEl("span", {
            text: r.risk_level,
            cls: riskClass(r.risk_level),
        });

        contentEl.createEl("p", {
            text: r.allowed ? "✅ Safe to share" : "⚠ Review required before sharing",
        });

        contentEl.createEl("hr", { cls: "warden-divider" });

        // Secrets
        if (r.secrets_found.length) {
            const sec = contentEl.createDiv("warden-section");
            sec.createDiv({
                text: `⚠ ${r.secrets_found.length} secret type(s) detected`,
                cls: "warden-section-title",
            });
            const tags = sec.createDiv();
            r.secrets_found.forEach(s => tags.createEl("span", { text: s, cls: "warden-tag" }));
        }

        // Flags
        if (r.flags.length) {
            const fl = contentEl.createDiv("warden-section");
            fl.createDiv({ text: "Flags", cls: "warden-section-title" });
            r.flags.forEach(f => fl.createEl("span", { text: f, cls: "warden-tag" }));
        }

        // Metadata
        const meta = contentEl.createDiv("warden-section");
        meta.createDiv({ text: "Metadata", cls: "warden-section-title" });
        meta.createEl("p", { text: `Data class: ${r.data_class}` });
        meta.createEl("p", { text: `Words: ${r.word_count}` });
        meta.createEl("p", { text: `File: ${r.filename || "—"}` });

        // Redacted content (if secrets found)
        if (r.secrets_found.length && r.redacted_content) {
            const red = contentEl.createDiv("warden-section");
            red.createDiv({ text: "Redacted version (safe to copy)", cls: "warden-section-title" });
            const pre = red.createEl("pre");
            pre.style.cssText = "max-height:200px;overflow:auto;font-size:0.78rem;";
            pre.createEl("code", { text: r.redacted_content.slice(0, 2000) });
        }
    }

    onClose() {
        this.contentEl.empty();
    }
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
        sec.createEl("p", {
            text: "UECIID",
            cls: "warden-section-title",
        });
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
            row.style.cssText = "display:flex;gap:12px;margin:4px 0;";
            row.createEl("span", { text: label, cls: "warden-section-title" });
            row.style.alignItems = "center";
            row.createEl("span", { text: value });
        });
    }

    onClose() {
        this.contentEl.empty();
    }
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
            contentEl.createEl("p", { text: "No notes shared yet. Use 'Share note to Community' to add one." });
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

    onClose() {
        this.contentEl.empty();
    }
}

// ── Main Plugin ───────────────────────────────────────────────────────────────

export default class WardenPlugin extends Plugin {
    settings: WardenSettings;
    private statusBarEl: HTMLElement;

    async onload() {
        await this.loadSettings();

        // Status bar
        this.statusBarEl = this.addStatusBarItem();
        this.statusBarEl.addClass("warden-status-bar");
        this.statusBarEl.setText("🛡 Warden");
        this.statusBarEl.title = "Shadow Warden AI — click to scan current note";
        this.statusBarEl.addEventListener("click", () => this.scanCurrentNote());

        // Ribbon icon
        this.addRibbonIcon("shield", "Shadow Warden — Scan Note", () =>
            this.scanCurrentNote()
        );

        // Commands
        this.addCommand({
            id: "scan-note",
            name: "Scan current note for secrets & PII",
            editorCallback: (_editor: Editor) => this.scanCurrentNote(),
        });

        this.addCommand({
            id: "share-note",
            name: "Share note to Business Community",
            editorCallback: (_editor: Editor) => this.shareCurrentNote(),
        });

        this.addCommand({
            id: "scan-vault",
            name: "Scan entire vault for secrets",
            callback: () => this.scanVault(),
        });

        this.addCommand({
            id: "community-feed",
            name: "View Business Community feed",
            callback: () => this.viewFeed(),
        });

        this.addCommand({
            id: "check-connection",
            name: "Check Warden connection",
            callback: () => this.checkConnection(),
        });

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
    }

    // ── HTTP helpers ────────────────────────────────────────────────────────

    private headers(): Record<string, string> {
        const h: Record<string, string> = { "Content-Type": "application/json" };
        if (this.settings.apiKey) h["X-API-Key"] = this.settings.apiKey;
        if (this.settings.tenantId) h["X-Tenant-ID"] = this.settings.tenantId;
        return h;
    }

    private async post(path: string, body: unknown): Promise<RequestUrlResponse | null> {
        try {
            return await requestUrl({
                url: `${this.settings.wardenUrl}${path}`,
                method: "POST",
                headers: this.headers(),
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
                headers: this.headers(),
                throw: false,
            });
        } catch (e) {
            new Notice(`Cannot reach Warden: ${e}`);
            return null;
        }
    }

    // ── Commands ────────────────────────────────────────────────────────────

    async scanCurrentNote() {
        const view = this.app.workspace.getActiveViewOfType(MarkdownView);
        if (!view) { new Notice("Open a markdown note first."); return; }

        const content = view.editor.getValue();
        const filename = view.file?.name ?? "";

        this.statusBarEl.setText("🛡 Scanning…");
        const resp = await this.post("/obsidian/scan", { content, filename });
        if (!resp) { this.statusBarEl.setText("🛡 Error"); return; }

        if (resp.status >= 400) {
            new Notice(`Warden error ${resp.status}: ${resp.text.slice(0, 120)}`);
            this.statusBarEl.setText("🛡 Error");
            return;
        }

        const result: ScanResult = resp.json;
        const icon = result.allowed ? "✅" : "⚠";
        this.statusBarEl.setText(`🛡 ${result.risk_level}`);
        new ScanResultModal(this.app, result).open();
    }

    async silentScan(file: TFile) {
        const content = await this.app.vault.read(file);
        const resp = await this.post("/obsidian/scan", { content, filename: file.name });
        if (!resp || resp.status >= 400) return;

        const result: ScanResult = resp.json;
        this.statusBarEl.setText(`🛡 ${result.risk_level}`);

        if (!result.allowed && this.settings.alertOnHigh) {
            new Notice(
                `⚠ Shadow Warden: ${result.risk_level} risk in "${file.name}"\n` +
                (result.secrets_found.length ? `Secrets: ${result.secrets_found.join(", ")}` : result.flags.join(", "))
            );
        }
    }

    async shareCurrentNote() {
        if (!this.settings.communityId) {
            new Notice("Set a Community ID in Shadow Warden settings (⚙ gear icon).");
            return;
        }

        const view = this.app.workspace.getActiveViewOfType(MarkdownView);
        if (!view) { new Notice("Open a markdown note first."); return; }

        const content = view.editor.getValue();
        const filename = view.file?.name ?? "Untitled.md";
        const displayName = filename.replace(/\.md$/i, "");

        new Notice("Scanning before share…");
        const resp = await this.post("/obsidian/share", {
            content,
            filename,
            display_name: displayName,
            community_id: this.settings.communityId,
        });

        if (!resp) return;
        if (resp.status === 400) {
            new Notice(`❌ Share blocked: ${resp.json?.detail ?? resp.text.slice(0, 120)}`);
            return;
        }
        if (resp.status >= 400) {
            new Notice(`Warden error ${resp.status}`);
            return;
        }

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
            if (!result.allowed) {
                issues++;
                flagged.push(`${file.name} [${result.risk_level}]`);
            }
        }

        if (issues === 0) {
            new Notice(`✅ Vault clean — ${files.length} notes scanned, no issues found.`);
        } else {
            new Notice(`⚠ ${issues} note(s) need review:\n${flagged.slice(0, 5).join("\n")}${flagged.length > 5 ? `\n…and ${flagged.length - 5} more` : ""}`);
        }
    }

    async viewFeed() {
        if (!this.settings.communityId) {
            new Notice("Set a Community ID in Shadow Warden settings.");
            return;
        }

        const resp = await this.get(
            `/obsidian/feed?community_id=${encodeURIComponent(this.settings.communityId)}&limit=50`
        );
        if (!resp) return;
        if (resp.status >= 400) { new Notice(`Feed error ${resp.status}`); return; }

        new FeedModal(this.app, resp.json as FeedEntry[], this.settings.communityId).open();
    }

    async checkConnection() {
        const resp = await this.get("/obsidian/stats");
        if (!resp) return;
        if (resp.status === 200) {
            const s = resp.json;
            new Notice(`✅ Connected to Shadow Warden v${s.version}\nTenant: ${s.tenant_id}\nStatus: ${s.status}`);
            this.statusBarEl.setText("🛡 Connected");
        } else {
            new Notice(`Connection failed: HTTP ${resp.status}`);
        }
    }

    // ── Settings ────────────────────────────────────────────────────────────

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
        containerEl.createEl("p", {
            text: "Business Community integration — scan notes, share via SEP, filter AI prompts.",
            cls: "setting-item-description",
        });

        // Connection
        containerEl.createEl("h3", { text: "Connection" });

        new Setting(containerEl)
            .setName("Warden URL")
            .setDesc("Base URL of your Shadow Warden instance (no trailing slash)")
            .addText(t =>
                t
                    .setPlaceholder("http://localhost:8000")
                    .setValue(this.plugin.settings.wardenUrl)
                    .onChange(async v => {
                        this.plugin.settings.wardenUrl = v.replace(/\/$/, "");
                        await this.plugin.saveSettings();
                    })
            );

        new Setting(containerEl)
            .setName("API Key")
            .setDesc("X-API-Key header (leave empty if ALLOW_UNAUTHENTICATED=true)")
            .addText(t =>
                t
                    .setPlaceholder("warden_prod_xxxx")
                    .setValue(this.plugin.settings.apiKey)
                    .onChange(async v => {
                        this.plugin.settings.apiKey = v;
                        await this.plugin.saveSettings();
                    })
            );

        new Setting(containerEl)
            .setName("Tenant ID")
            .setDesc("Your tenant identifier (X-Tenant-ID header)")
            .addText(t =>
                t
                    .setPlaceholder("default")
                    .setValue(this.plugin.settings.tenantId)
                    .onChange(async v => {
                        this.plugin.settings.tenantId = v || "default";
                        await this.plugin.saveSettings();
                    })
            );

        // Community
        containerEl.createEl("h3", { text: "Business Community" });

        new Setting(containerEl)
            .setName("Community ID")
            .setDesc("Your community ID for note sharing and feed (e.g. comm-abc123)")
            .addText(t =>
                t
                    .setPlaceholder("comm-xxxxxxxx")
                    .setValue(this.plugin.settings.communityId)
                    .onChange(async v => {
                        this.plugin.settings.communityId = v;
                        await this.plugin.saveSettings();
                    })
            );

        // Behaviour
        containerEl.createEl("h3", { text: "Behaviour" });

        new Setting(containerEl)
            .setName("Auto-scan on save")
            .setDesc("Silently scan the active note every time it is modified (requires restart to take effect)")
            .addToggle(t =>
                t
                    .setValue(this.plugin.settings.autoScanOnSave)
                    .onChange(async v => {
                        this.plugin.settings.autoScanOnSave = v;
                        await this.plugin.saveSettings();
                    })
            );

        new Setting(containerEl)
            .setName("Alert on HIGH / BLOCK")
            .setDesc("Show a notice when auto-scan detects high-risk content")
            .addToggle(t =>
                t
                    .setValue(this.plugin.settings.alertOnHigh)
                    .onChange(async v => {
                        this.plugin.settings.alertOnHigh = v;
                        await this.plugin.saveSettings();
                    })
            );

        // Test connection button
        containerEl.createEl("h3", { text: "Diagnostics" });
        new Setting(containerEl)
            .setName("Test connection")
            .setDesc("Verify Warden is reachable and responding")
            .addButton(b =>
                b
                    .setButtonText("Check connection")
                    .setCta()
                    .onClick(() => this.plugin.checkConnection())
            );
    }
}
