/**
 * Shadow Warden AI — VS Code Extension  (IN-14)
 * ───────────────────────────────────────────────
 * Inline risk annotation for selected text, files, and clipboard.
 *
 * Commands
 * ────────
 *   Ctrl+Shift+W  → shadowWarden.scan           — scan selection
 *   (context menu) → shadowWarden.scanFile       — scan whole file (concurrent)
 *                  → shadowWarden.scanClipboard  — scan clipboard text
 *                  → shadowWarden.clearDecorations
 *                  → shadowWarden.openSettings
 *
 * Decorations (4 tiers)
 * ─────────────────────
 *   LOW / PASS / ALLOW  → subtle green tint
 *   MEDIUM / FLAG       → yellow tint  + `⚠ MEDIUM` after text
 *   HIGH                → orange tint  + `⛔ HIGH`   after text
 *   BLOCK               → red tint+border + `🚫 BLOCK` after text
 *
 * Code Lens
 * ─────────
 *   HIGH and BLOCK annotated lines get a code lens above them:
 *     ⚠ Shadow Warden: HIGH — jailbreak_attempt  [details]
 */

import * as http  from "http";
import * as https from "https";
import { URL }    from "url";
import * as vscode from "vscode";

// ── Types ─────────────────────────────────────────────────────────────────────

interface FilterResponse {
  allowed:        boolean;
  risk_level:     string;   // ALLOW | LOW | MEDIUM | HIGH | BLOCK
  flags:          string[];
  secrets_found:  string[];
  processing_ms:  number;
  request_id?:    string;
  blocked?:       boolean;
}

interface Annotation {
  range:    vscode.Range;
  verdict:  string;
  score:    number;
  flags:    string[];
  secrets:  string[];
  reqId?:   string;
}

// ── Config ────────────────────────────────────────────────────────────────────

const cfg     = () => vscode.workspace.getConfiguration("shadowWarden");
const apiUrl  = () => cfg().get<string>("apiUrl",      "https://api.shadow-warden-ai.com");
const apiKey  = () => cfg().get<string>("apiKey",      "");
const tenantId= () => cfg().get<string>("tenantId",    "");
const minRisk = () => cfg().get<string>("minRiskLevel","MEDIUM");
const showDec = () => cfg().get<boolean>("showInlineDecorations", true);
const showLens= () => cfg().get<boolean>("showCodeLens", true);
const conc    = () => Math.max(1, Math.min(16, cfg().get<number>("concurrency", 4)));

// ── Risk ordering ─────────────────────────────────────────────────────────────

const RISK_ORDER: Record<string, number> = {
  ALLOW: 0, PASS: 0, LOW: 1, MEDIUM: 2, FLAG: 2, HIGH: 3, BLOCK: 4,
};

function riskNum(v: string): number {
  return RISK_ORDER[v.toUpperCase()] ?? 1;
}

function meetsMin(v: string): boolean {
  return riskNum(v) >= riskNum(minRisk());
}

// ── Decoration types (4 tiers) ────────────────────────────────────────────────

const _dLow = vscode.window.createTextEditorDecorationType({
  overviewRulerColor: "#30D158",
  overviewRulerLane:   vscode.OverviewRulerLane.Left,
  backgroundColor:     "rgba(48,209,88,0.05)",
  // Gutter icon (DEV-03): green shield
  gutterIconPath:  vscode.Uri.parse("data:image/svg+xml," + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path fill="#30D158" d="M8 1L2 4v4c0 3.31 2.52 6.41 6 7 3.48-.59 6-3.69 6-7V4L8 1z"/></svg>'
  )),
  gutterIconSize: "contain",
});

const _dMedium = vscode.window.createTextEditorDecorationType({
  overviewRulerColor: "#FFD60A",
  overviewRulerLane:   vscode.OverviewRulerLane.Left,
  backgroundColor:     "rgba(255,214,10,0.08)",
  // Gutter icon: yellow warning shield
  gutterIconPath: vscode.Uri.parse("data:image/svg+xml," + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path fill="#FFD60A" d="M8 1L2 4v4c0 3.31 2.52 6.41 6 7 3.48-.59 6-3.69 6-7V4L8 1z"/><text x="8" y="11" text-anchor="middle" font-size="7" fill="#000">!</text></svg>'
  )),
  gutterIconSize: "contain",
});

const _dHigh = vscode.window.createTextEditorDecorationType({
  overviewRulerColor: "#FF8C42",
  overviewRulerLane:   vscode.OverviewRulerLane.Right,
  backgroundColor:     "rgba(255,140,66,0.10)",
  borderWidth:         "0 0 0 2px",
  borderStyle:         "solid",
  borderColor:         "rgba(255,140,66,0.40)",
  // Gutter icon: orange shield
  gutterIconPath: vscode.Uri.parse("data:image/svg+xml," + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path fill="#FF8C42" d="M8 1L2 4v4c0 3.31 2.52 6.41 6 7 3.48-.59 6-3.69 6-7V4L8 1z"/></svg>'
  )),
  gutterIconSize: "contain",
});

const _dBlock = vscode.window.createTextEditorDecorationType({
  overviewRulerColor: "#FF2D55",
  overviewRulerLane:   vscode.OverviewRulerLane.Right,
  backgroundColor:     "rgba(255,45,85,0.12)",
  borderWidth:         "0 0 0 3px",
  borderStyle:         "solid",
  borderColor:         "rgba(255,45,85,0.60)",
  // Gutter icon: red blocked shield
  gutterIconPath: vscode.Uri.parse("data:image/svg+xml," + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path fill="#FF2D55" d="M8 1L2 4v4c0 3.31 2.52 6.41 6 7 3.48-.59 6-3.69 6-7V4L8 1z"/><line x1="5" y1="5" x2="11" y2="11" stroke="#fff" stroke-width="2"/><line x1="11" y1="5" x2="5" y2="11" stroke="#fff" stroke-width="2"/></svg>'
  )),
  gutterIconSize: "contain",
});

// Inline after-text showing verdict (per-decoration renderOptions)
const _afterMedium: vscode.DecorationInstanceRenderOptions = {
  after: { contentText: "  ⚠ MEDIUM", color: "#FFD60A", fontStyle: "italic", margin: "0 0 0 4px" },
};
const _afterHigh: vscode.DecorationInstanceRenderOptions = {
  after: { contentText: "  ⛔ HIGH", color: "#FF8C42", fontStyle: "italic", margin: "0 0 0 4px" },
};
const _afterBlock: vscode.DecorationInstanceRenderOptions = {
  after: { contentText: "  🚫 BLOCK", color: "#FF2D55", fontWeight: "bold", margin: "0 0 0 4px" },
};

// ── Output channel ────────────────────────────────────────────────────────────

const _out = vscode.window.createOutputChannel("Shadow Warden AI");

function log(msg: string) {
  _out.appendLine(`[${new Date().toISOString()}] ${msg}`);
}

// ── Diagnostics ───────────────────────────────────────────────────────────────

const _diag = vscode.languages.createDiagnosticCollection("shadowWarden");

function addDiagnostic(doc: vscode.TextDocument, ann: Annotation) {
  const v = ann.verdict.toUpperCase();
  if (v !== "HIGH" && v !== "BLOCK") { return; }
  const sev = v === "BLOCK"
    ? vscode.DiagnosticSeverity.Error
    : vscode.DiagnosticSeverity.Warning;
  const detail = [
    ann.flags.length   ? `flags: ${ann.flags.join(", ")}`   : "",
    ann.secrets.length ? `secrets: ${ann.secrets.join(", ")}` : "",
  ].filter(Boolean).join(" · ");
  const d = new vscode.Diagnostic(
    ann.range,
    `Shadow Warden: ${v}${detail ? " — " + detail : ""}`,
    sev,
  );
  d.source = "Shadow Warden AI";
  const prev = _diag.get(doc.uri) ?? [];
  _diag.set(doc.uri, [...prev, d]);
}

// ── Annotation store ──────────────────────────────────────────────────────────

const _store = new Map<string, Annotation[]>();

function getAnns(uri: vscode.Uri): Annotation[] {
  return _store.get(uri.toString()) ?? [];
}

function addAnn(uri: vscode.Uri, ann: Annotation) {
  const key = uri.toString();
  _store.set(key, [...(_store.get(key) ?? []), ann]);
}

function clearAnns(uri: vscode.Uri) {
  _store.delete(uri.toString());
}

// ── Apply decorations ─────────────────────────────────────────────────────────

function applyDecorations(editor: vscode.TextEditor) {
  const anns = getAnns(editor.document.uri);
  const low:    vscode.DecorationOptions[] = [];
  const medium: vscode.DecorationOptions[] = [];
  const high:   vscode.DecorationOptions[] = [];
  const block:  vscode.DecorationOptions[] = [];

  for (const a of anns) {
    const v = a.verdict.toUpperCase();
    const hover = buildHover(a);
    const opt: vscode.DecorationOptions = { range: a.range, hoverMessage: hover };

    if (v === "BLOCK") {
      block.push({ ...opt, renderOptions: _afterBlock });
    } else if (v === "HIGH") {
      high.push({ ...opt, renderOptions: _afterHigh });
    } else if (v === "MEDIUM" || v === "FLAG") {
      medium.push({ ...opt, renderOptions: _afterMedium });
    } else {
      low.push(opt);
    }
  }

  editor.setDecorations(_dLow,    low);
  editor.setDecorations(_dMedium, medium);
  editor.setDecorations(_dHigh,   high);
  editor.setDecorations(_dBlock,  block);
}

function buildHover(a: Annotation): vscode.MarkdownString {
  const v    = a.verdict.toUpperCase();
  const icon = v === "BLOCK" ? "🚫" : v === "HIGH" ? "⛔" : v === "MEDIUM" ? "⚠" : "✅";
  const md   = new vscode.MarkdownString("", true);
  md.isTrusted = true;
  md.appendMarkdown(`**Shadow Warden AI — ${icon} ${v}**\n\n`);
  if (a.score)   { md.appendMarkdown(`Score: \`${a.score.toFixed(3)}\`\n\n`); }
  if (a.flags.length)   { md.appendMarkdown(`Flags: ${a.flags.map(f => `\`${f}\``).join(", ")}\n\n`); }
  if (a.secrets.length) { md.appendMarkdown(`Secrets detected: ${a.secrets.map(s => `\`${s}\``).join(", ")}\n\n`); }
  if (a.reqId)   { md.appendMarkdown(`Request ID: \`${a.reqId}\`\n\n`); }
  md.appendMarkdown(`[Clear annotations](command:shadowWarden.clearDecorations)`);
  return md;
}

// ── Code Lens provider ────────────────────────────────────────────────────────

class WardenCodeLensProvider implements vscode.CodeLensProvider {
  private _emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._emitter.event;

  fire() { this._emitter.fire(); }

  provideCodeLenses(doc: vscode.TextDocument): vscode.CodeLens[] {
    if (!showLens()) { return []; }
    return getAnns(doc.uri)
      .filter(a => riskNum(a.verdict) >= riskNum("HIGH"))
      .map(a => {
        const v     = a.verdict.toUpperCase();
        const icon  = v === "BLOCK" ? "🚫" : "⛔";
        const flags = a.flags.length ? ` — ${a.flags.slice(0, 2).join(", ")}` : "";
        const title = `${icon} Shadow Warden: ${v}${flags}`;
        return new vscode.CodeLens(a.range, {
          title,
          command: "shadowWarden.clearDecorations",
          tooltip: "Click to clear all annotations",
        });
      });
  }
}

const _lensProvider = new WardenCodeLensProvider();

// ── Status bar ────────────────────────────────────────────────────────────────

let _bar: vscode.StatusBarItem;

function status(msg: string, color?: string) {
  _bar.text  = `$(shield) ${msg}`;
  _bar.color = color;
  _bar.show();
}

// ── HTTP (no extra dependencies) ──────────────────────────────────────────────

function postFilter(text: string, context = "vscode_selection"): Promise<FilterResponse> {
  return new Promise((resolve, reject) => {
    if (!apiKey()) {
      reject(new Error("API key not configured — open Shadow Warden settings (Ctrl+Shift+W)"));
      return;
    }
    const base = apiUrl();
    const url  = new URL("/filter", base);
    const body = JSON.stringify({
      content:   text,
      context,
      ...(tenantId() ? { tenant_id: tenantId() } : {}),
    });
    const opts: http.RequestOptions = {
      hostname: url.hostname,
      port:     url.port || (url.protocol === "https:" ? "443" : "80"),
      path:     url.pathname,
      method:   "POST",
      headers:  {
        "Content-Type":   "application/json",
        "Content-Length": Buffer.byteLength(body),
        "X-API-Key":      apiKey(),
      },
      timeout: 10_000,
    };
    const transport = url.protocol === "https:" ? https : http;
    const req = transport.request(opts, (res) => {
      let raw = "";
      res.on("data", (c) => (raw += c));
      res.on("end", () => {
        try { resolve(JSON.parse(raw) as FilterResponse); }
        catch { reject(new Error(`Bad JSON from API: ${raw.slice(0, 120)}`)); }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Request timed out (10 s)")); });
    req.write(body);
    req.end();
  });
}

// ── Semaphore for concurrent file scan ────────────────────────────────────────

class Semaphore {
  private slots: number;
  private queue: (() => void)[] = [];
  constructor(n: number) { this.slots = n; }
  acquire(): Promise<void> {
    if (this.slots > 0) { this.slots--; return Promise.resolve(); }
    return new Promise<void>((r) => this.queue.push(r));
  }
  release() {
    if (this.queue.length > 0) { (this.queue.shift()!)(); } else { this.slots++; }
  }
}

// ── Core scan ─────────────────────────────────────────────────────────────────

async function scanRange(
  editor: vscode.TextEditor,
  range:  vscode.Range,
  context = "vscode_selection",
): Promise<Annotation | null> {
  const text = editor.document.getText(range).trim();
  if (!text) { return null; }

  try {
    const res = await postFilter(text, context);
    const verdict = res.risk_level ?? "ALLOW";
    const ann: Annotation = {
      range,
      verdict,
      score:   res.processing_ms ? +(res.processing_ms / 100).toFixed(3) : 0,
      flags:   res.flags   ?? [],
      secrets: res.secrets_found ?? [],
      reqId:   res.request_id,
    };
    log(
      `${verdict} | flags=[${ann.flags.join(",")}] secrets=[${ann.secrets.join(",")}]` +
      ` | ${res.processing_ms?.toFixed(1) ?? "?"}ms | ${text.slice(0, 80).replace(/\n/g, "↵")}`,
    );
    return ann;
  } catch (err: unknown) {
    log(`ERROR: ${err instanceof Error ? err.message : String(err)}`);
    throw err;
  }
}

// ── Commands ──────────────────────────────────────────────────────────────────

async function cmdScan() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) { return; }
  const sel = editor.selection;
  if (sel.isEmpty) {
    vscode.window.showWarningMessage("Shadow Warden: select text first (or use Scan File).");
    return;
  }
  status("Scanning…", "#FFD60A");
  try {
    const ann = await scanRange(editor, sel);
    if (!ann) { status("Empty selection", "#8E8E9E"); return; }

    if (showDec() && meetsMin(ann.verdict)) {
      addAnn(editor.document.uri, ann);
      applyDecorations(editor);
      addDiagnostic(editor.document, ann);
      _lensProvider.fire();
    }

    const v = ann.verdict.toUpperCase();
    const color =
      v === "BLOCK"  ? "#FF2D55" :
      v === "HIGH"   ? "#FF8C42" :
      v === "MEDIUM" || v === "FLAG" ? "#FFD60A" : "#30D158";
    status(`${ann.verdict}${ann.flags.length ? " · " + ann.flags[0] : ""}`, color);

    if (v === "BLOCK" || v === "HIGH") {
      const detail = ann.flags.length ? ` (${ann.flags.join(", ")})` : "";
      vscode.window.showWarningMessage(
        `Shadow Warden: ${v} risk detected${detail}`,
        "Show Output",
      ).then(s => { if (s) { _out.show(); } });
    }
  } catch (err: unknown) {
    status("Error", "#FF2D55");
    vscode.window.showErrorMessage(`Shadow Warden: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function cmdScanFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) { return; }
  const doc = editor.document;

  const lines = Array.from({ length: doc.lineCount }, (_, i) => doc.lineAt(i))
    .filter(l => !l.isEmptyOrWhitespace);

  if (lines.length === 0) {
    vscode.window.showInformationMessage("Shadow Warden: file is empty.");
    return;
  }

  status(`Scanning ${lines.length} lines…`, "#FFD60A");
  _diag.delete(doc.uri);
  clearAnns(doc.uri);

  const sem = new Semaphore(conc());
  let high = 0, block = 0, errors = 0;

  await Promise.all(lines.map(async (line) => {
    await sem.acquire();
    try {
      const ann = await scanRange(editor, line.range, "vscode_file");
      if (ann && meetsMin(ann.verdict)) {
        addAnn(doc.uri, ann);
        addDiagnostic(doc, ann);
        const v = ann.verdict.toUpperCase();
        if (v === "HIGH")  { high++; }
        if (v === "BLOCK") { block++; }
      }
    } catch { errors++; }
    finally { sem.release(); }
  }));

  applyDecorations(editor);
  _lensProvider.fire();

  const col = block > 0 ? "#FF2D55" : high > 0 ? "#FF8C42" : "#30D158";
  const summary = `File done — ${block} BLOCK, ${high} HIGH${errors ? `, ${errors} err` : ""}`;
  status(summary, col);
  log(`File scan complete: ${lines.length} lines, ${block} BLOCK, ${high} HIGH, ${errors} errors`);
}

async function cmdScanClipboard() {
  const text = await vscode.env.clipboard.readText();
  if (!text.trim()) {
    vscode.window.showWarningMessage("Shadow Warden: clipboard is empty.");
    return;
  }
  status("Scanning clipboard…", "#FFD60A");
  try {
    const res = await postFilter(text, "vscode_clipboard");
    const verdict = res.risk_level ?? "ALLOW";
    const flags   = res.flags ?? [];
    const secrets = res.secrets_found ?? [];
    log(`Clipboard: ${verdict} | flags=[${flags.join(",")}] secrets=[${secrets.join(",")}]`);

    const v = verdict.toUpperCase();
    const detail = [
      flags.length   ? `Flags: ${flags.join(", ")}` : "",
      secrets.length ? `Secrets: ${secrets.join(", ")}` : "",
    ].filter(Boolean).join(" · ");
    const msg = `Shadow Warden: clipboard is **${v}**${detail ? " — " + detail : ""}`;

    const color = v === "BLOCK" ? "#FF2D55" : v === "HIGH" ? "#FF8C42" :
                  v === "MEDIUM" ? "#FFD60A" : "#30D158";
    status(`Clipboard: ${verdict}`, color);
    vscode.window.showInformationMessage(msg, "Show Output").then(s => { if (s) { _out.show(); } });
  } catch (err: unknown) {
    status("Error", "#FF2D55");
    vscode.window.showErrorMessage(`Shadow Warden clipboard scan failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function cmdClear() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) { return; }
  clearAnns(editor.document.uri);
  editor.setDecorations(_dLow,    []);
  editor.setDecorations(_dMedium, []);
  editor.setDecorations(_dHigh,   []);
  editor.setDecorations(_dBlock,  []);
  _diag.delete(editor.document.uri);
  _lensProvider.fire();
  status("Cleared", "#30D158");
  setTimeout(() => _bar.hide(), 2000);
}

function cmdOpenSettings() {
  vscode.commands.executeCommand(
    "workbench.action.openSettings",
    "@ext:shadow-warden-ai.shadow-warden-ai",
  );
}

// ── Auto-scan on save ─────────────────────────────────────────────────────────

function onSave(doc: vscode.TextDocument) {
  if (!cfg().get<boolean>("autoScanOnSave", false)) { return; }
  const editor = vscode.window.visibleTextEditors.find(
    e => e.document.uri.toString() === doc.uri.toString(),
  );
  if (!editor) { return; }
  cmdScanFile();
}

// ── Activation ────────────────────────────────────────────────────────────────

export function activate(ctx: vscode.ExtensionContext) {
  _bar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  _bar.command = "shadowWarden.scan";
  _bar.tooltip = "Shadow Warden AI — click to scan selection";
  ctx.subscriptions.push(_bar);

  // Show "configure" hint if no API key
  if (!apiKey()) {
    status("Configure API key", "#FF8C42");
  }

  ctx.subscriptions.push(
    vscode.commands.registerCommand("shadowWarden.scan",              cmdScan),
    vscode.commands.registerCommand("shadowWarden.scanFile",          cmdScanFile),
    vscode.commands.registerCommand("shadowWarden.scanClipboard",     cmdScanClipboard),
    vscode.commands.registerCommand("shadowWarden.clearDecorations",  cmdClear),
    vscode.commands.registerCommand("shadowWarden.openSettings",      cmdOpenSettings),

    vscode.workspace.onDidSaveTextDocument(onSave),
    vscode.window.onDidChangeActiveTextEditor(e => { if (e) { applyDecorations(e); } }),

    vscode.languages.registerCodeLensProvider({ scheme: "*" }, _lensProvider),

    _diag,
    _out,
  );

  log(`Shadow Warden AI activated (api=${apiUrl()}, key=${apiKey() ? "set" : "MISSING"})`);
}

export function deactivate() {
  _dLow.dispose();
  _dMedium.dispose();
  _dHigh.dispose();
  _dBlock.dispose();
  _diag.dispose();
  _out.dispose();
}
