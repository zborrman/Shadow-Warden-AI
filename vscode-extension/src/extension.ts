import * as vscode from "vscode";
import * as https from "https";
import * as http from "http";
import { URL } from "url";

// ── Decoration types ──────────────────────────────────────────────────────────

const _decorAllow = vscode.window.createTextEditorDecorationType({
  gutterIconPath: undefined,
  overviewRulerColor: "#30D158",
  overviewRulerLane: vscode.OverviewRulerLane.Left,
  backgroundColor: "rgba(48,209,88,0.06)",
});

const _decorMedium = vscode.window.createTextEditorDecorationType({
  overviewRulerColor: "#FFD60A",
  overviewRulerLane: vscode.OverviewRulerLane.Left,
  backgroundColor: "rgba(255,214,10,0.08)",
});

const _decorHigh = vscode.window.createTextEditorDecorationType({
  overviewRulerColor: "#FF2D55",
  overviewRulerLane: vscode.OverviewRulerLane.Left,
  backgroundColor: "rgba(255,45,85,0.1)",
});

// ── Config helpers ─────────────────────────────────────────────────────────────

function cfg() {
  return vscode.workspace.getConfiguration("shadowWarden");
}

function apiUrl(): string {
  return cfg().get<string>("apiUrl", "https://api.shadow-warden-ai.com");
}

function apiKey(): string {
  return cfg().get<string>("apiKey", "");
}

function minRisk(): string {
  return cfg().get<string>("minRiskLevel", "MEDIUM");
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

interface FilterResponse {
  verdict: string;
  score: number;
  flags?: string[];
  processing_ms?: number;
}

function postFilter(text: string): Promise<FilterResponse> {
  return new Promise((resolve, reject) => {
    const base = apiUrl();
    const url = new URL("/filter", base);
    const body = JSON.stringify({ text });
    const opts: http.RequestOptions = {
      hostname: url.hostname,
      port: url.port || (url.protocol === "https:" ? 443 : 80),
      path: url.pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
        ...(apiKey() ? { "X-API-Key": apiKey() } : {}),
      },
      timeout: 10000,
    };
    const transport = url.protocol === "https:" ? https : http;
    const req = transport.request(opts, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data) as FilterResponse);
        } catch {
          reject(new Error(`Invalid JSON: ${data.slice(0, 100)}`));
        }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timed out"));
    });
    req.write(body);
    req.end();
  });
}

// ── Risk classification ───────────────────────────────────────────────────────

const _RISK_ORDER = ["ALLOW", "PASS", "LOW", "MEDIUM", "FLAG", "HIGH", "BLOCK"];

function riskLevel(verdict: string): number {
  const idx = _RISK_ORDER.indexOf(verdict.toUpperCase());
  return idx === -1 ? 3 : idx;
}

function meetsMinRisk(verdict: string): boolean {
  return riskLevel(verdict) >= riskLevel(minRisk());
}

function decorFor(verdict: string) {
  const v = verdict.toUpperCase();
  if (v === "HIGH" || v === "BLOCK") return _decorHigh;
  if (v === "MEDIUM" || v === "FLAG") return _decorMedium;
  return _decorAllow;
}

// ── Diagnostics ───────────────────────────────────────────────────────────────

const _diagCollection = vscode.languages.createDiagnosticCollection("shadowWarden");

function pushDiagnostic(
  doc: vscode.TextDocument,
  range: vscode.Range,
  verdict: string,
  score: number
) {
  const v = verdict.toUpperCase();
  if (v !== "HIGH" && v !== "BLOCK") return;
  const sev = v === "BLOCK" ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning;
  const diag = new vscode.Diagnostic(
    range,
    `Shadow Warden: ${verdict} (score ${score.toFixed(2)}) — potential AI security risk`,
    sev
  );
  diag.source = "Shadow Warden AI";
  const existing = _diagCollection.get(doc.uri) ?? [];
  _diagCollection.set(doc.uri, [...existing, diag]);
}

// ── Status bar ────────────────────────────────────────────────────────────────

let _statusBar: vscode.StatusBarItem;

function showStatus(msg: string, color?: string) {
  _statusBar.text = `$(shield) ${msg}`;
  _statusBar.color = color;
  _statusBar.show();
}

// ── Core scan logic ───────────────────────────────────────────────────────────

interface ScanAnnotation {
  range: vscode.Range;
  verdict: string;
  score: number;
}

const _annotations = new Map<string, ScanAnnotation[]>();

function applyAnnotations(editor: vscode.TextEditor) {
  const key = editor.document.uri.toString();
  const ann = _annotations.get(key) ?? [];
  const allow: vscode.DecorationOptions[] = [];
  const medium: vscode.DecorationOptions[] = [];
  const high: vscode.DecorationOptions[] = [];
  for (const a of ann) {
    const opts: vscode.DecorationOptions = {
      range: a.range,
      hoverMessage: `Shadow Warden: **${a.verdict}** (score ${a.score.toFixed(2)})`,
    };
    const v = a.verdict.toUpperCase();
    if (v === "HIGH" || v === "BLOCK") high.push(opts);
    else if (v === "MEDIUM" || v === "FLAG") medium.push(opts);
    else allow.push(opts);
  }
  editor.setDecorations(_decorAllow, allow);
  editor.setDecorations(_decorMedium, medium);
  editor.setDecorations(_decorHigh, high);
}

async function scanRange(
  editor: vscode.TextEditor,
  range: vscode.Range
): Promise<void> {
  const text = editor.document.getText(range);
  if (!text.trim()) {
    vscode.window.showWarningMessage("Shadow Warden: no text selected.");
    return;
  }
  showStatus("Scanning…", "#FFD60A");
  try {
    const result = await postFilter(text);
    const { verdict, score } = result;

    if (cfg().get<boolean>("showInlineDecorations", true) && meetsMinRisk(verdict)) {
      const key = editor.document.uri.toString();
      const existing = _annotations.get(key) ?? [];
      existing.push({ range, verdict, score });
      _annotations.set(key, existing);
      applyAnnotations(editor);
    }

    pushDiagnostic(editor.document, range, verdict, score);

    const color =
      verdict.toUpperCase() === "BLOCK" || verdict.toUpperCase() === "HIGH"
        ? "#FF2D55"
        : verdict.toUpperCase() === "MEDIUM" || verdict.toUpperCase() === "FLAG"
        ? "#FFD60A"
        : "#30D158";
    showStatus(`${verdict} · ${score.toFixed(2)}`, color);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    showStatus("Error", "#FF2D55");
    vscode.window.showErrorMessage(`Shadow Warden scan failed: ${msg}`);
  }
}

// ── Commands ──────────────────────────────────────────────────────────────────

async function cmdScan() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  const sel = editor.selection;
  if (sel.isEmpty) {
    vscode.window.showWarningMessage("Shadow Warden: select text to scan.");
    return;
  }
  await scanRange(editor, sel);
}

async function cmdScanFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  const doc = editor.document;
  showStatus("Scanning file…", "#FFD60A");

  // Chunk into lines; scan each non-empty line individually
  const lineCount = doc.lineCount;
  let highCount = 0;
  let blockCount = 0;

  for (let i = 0; i < lineCount; i++) {
    const line = doc.lineAt(i);
    if (line.isEmptyOrWhitespace) continue;
    try {
      const result = await postFilter(line.text);
      const { verdict, score } = result;
      if (meetsMinRisk(verdict)) {
        const key = doc.uri.toString();
        const existing = _annotations.get(key) ?? [];
        existing.push({ range: line.range, verdict, score });
        _annotations.set(key, existing);
        pushDiagnostic(doc, line.range, verdict, score);
        if (verdict.toUpperCase() === "HIGH") highCount++;
        if (verdict.toUpperCase() === "BLOCK") blockCount++;
      }
    } catch {
      // fail-open: continue scanning remaining lines
    }
  }

  applyAnnotations(editor);
  const color = blockCount > 0 ? "#FF2D55" : highCount > 0 ? "#FF8C42" : "#30D158";
  showStatus(`File scan done — ${blockCount} BLOCK, ${highCount} HIGH`, color);
}

function cmdClearDecorations() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  const key = editor.document.uri.toString();
  _annotations.delete(key);
  editor.setDecorations(_decorAllow, []);
  editor.setDecorations(_decorMedium, []);
  editor.setDecorations(_decorHigh, []);
  _diagCollection.delete(editor.document.uri);
  showStatus("Cleared", "#30D158");
  setTimeout(() => _statusBar.hide(), 2000);
}

function cmdOpenSettings() {
  vscode.commands.executeCommand(
    "workbench.action.openSettings",
    "@ext:shadow-warden-ai.shadow-warden-ai"
  );
}

// ── Auto-scan on save ─────────────────────────────────────────────────────────

function onDidSave(doc: vscode.TextDocument) {
  if (!cfg().get<boolean>("autoScanOnSave", false)) return;
  const editor = vscode.window.visibleTextEditors.find(
    (e) => e.document.uri.toString() === doc.uri.toString()
  );
  if (!editor) return;
  const fullRange = new vscode.Range(
    doc.positionAt(0),
    doc.positionAt(doc.getText().length)
  );
  scanRange(editor, fullRange);
}

// ── Activation ────────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
  _statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  _statusBar.command = "shadowWarden.scan";
  context.subscriptions.push(_statusBar);

  context.subscriptions.push(
    vscode.commands.registerCommand("shadowWarden.scan", cmdScan),
    vscode.commands.registerCommand("shadowWarden.scanFile", cmdScanFile),
    vscode.commands.registerCommand("shadowWarden.clearDecorations", cmdClearDecorations),
    vscode.commands.registerCommand("shadowWarden.openSettings", cmdOpenSettings),
    vscode.workspace.onDidSaveTextDocument(onDidSave),
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) applyAnnotations(editor);
    }),
    _diagCollection
  );
}

export function deactivate() {
  _decorAllow.dispose();
  _decorMedium.dispose();
  _decorHigh.dispose();
  _diagCollection.dispose();
}
