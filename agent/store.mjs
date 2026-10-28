// agent/store.mjs
// Persistent session memory: a JSONL "transcript" of every user/model/tool/handoff
// event, plus a distilled learnings.md the agent appends to ("learns as we proceed").
import fs from "node:fs";
import path from "node:path";

function truncate(s, n = 3000) { s = String(s ?? ""); return s.length > n ? s.slice(0, n) + " …(truncated)" : s; }

export class Store {
  constructor(root) {
    this.root = root;
    this.dir = path.join(root, "memory");
    fs.mkdirSync(this.dir, { recursive: true });
    this.sessionId = new Date().toISOString().replace(/[:.]/g, "-");
    this.file = path.join(this.dir, this.sessionId + ".jsonl");
    this.learnings = path.join(this.dir, "learnings.md");
    if (!fs.existsSync(this.learnings)) fs.writeFileSync(this.learnings, "# Learnings / handoffs\n\n(Durable notes the agent records as it works.)\n");
  }
  _append(entry) { fs.appendFileSync(this.file, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n"); }
  user(text) { this._append({ type: "user", text }); }
  model(content, toolCalls) { this._append({ type: "model", content: content || "", toolCalls: toolCalls || [] }); }
  tool(name, args, resultText, isError) { this._append({ type: "tool", tool: name, args, result: truncate(resultText), isError: !!isError }); }
  handoff(note) { this._append({ type: "handoff", note }); }
  remember(text) { fs.appendFileSync(this.learnings, "- [" + new Date().toISOString() + "] " + String(text).replace(/\n/g, " ") + "\n"); }
  // Recent durable learnings (for injection into the system prompt at each step).
  learningsTail(maxChars = 2500) {
    try {
      const lines = fs.readFileSync(this.learnings, "utf8").split("\n").filter((l) => l.startsWith("- ["));
      if (!lines.length) return "";
      const out = lines.slice(-40).join("\n");
      return out.length > maxChars ? "…" + out.slice(-maxChars) : out;
    } catch { return ""; }
  }
  // Search learnings + past session transcripts (excludes the live session file).
  searchMemory(query, maxResults = 10) {
    const q = String(query || "").toLowerCase().trim();
    if (!q) return "(empty query)";
    const hits = [];
    try {
      for (const l of fs.readFileSync(this.learnings, "utf8").split("\n"))
        if (l.startsWith("- [") && l.toLowerCase().includes(q)) hits.push("learnings: " + l.slice(0, 300));
    } catch {}
    let files = [];
    try { files = fs.readdirSync(this.dir).filter((f) => f.endsWith(".jsonl") && f !== path.basename(this.file)).sort(); } catch {}
    for (const f of files.slice(-10)) {
      try {
        for (const l of fs.readFileSync(path.join(this.dir, f), "utf8").split("\n").filter(Boolean)) {
          if (!l.toLowerCase().includes(q)) continue;
          try {
            const e = JSON.parse(l);
            const txt = String(e.text || e.note || e.result || e.content || "");
            if (txt.toLowerCase().includes(q)) hits.push(`${f.slice(0, 19)} ${e.type}${e.tool ? ":" + e.tool : ""}: ` + txt.slice(0, 250));
          } catch {}
        }
      } catch {}
    }
    return hits.length ? hits.slice(0, maxResults).join("\n") : "(no memory matches for: " + query + ")";
  }
  entries(n = 500) {
    if (!fs.existsSync(this.file)) return [];
    const lines = fs.readFileSync(this.file, "utf8").trim().split("\n").filter(Boolean);
    return lines.slice(-n).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  }
  recent(n = 12) { return this.entries(500).slice(-n); }
  summary() {
    const all = this.entries(500);
    return {
      file: this.file,
      learnings: this.learnings,
      entries: all.length,
      toolCalls: all.filter((e) => e.type === "tool").length,
      handoffs: all.filter((e) => e.type === "handoff").length,
    };
  }
}
