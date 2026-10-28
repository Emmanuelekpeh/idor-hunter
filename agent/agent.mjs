// agent/agent.mjs
// The semi-autonomous bug-bounty pilot. One Ollama 8b model directs Burp MCP tools.
// "Burst" = it keeps acting (issuing tool calls) until it (a) finishes, (b) asks the
// operator a question, or (c) has something to say / needs a decision. Human gates
// guard every risky Burp action so you stay in the loop.
import { chat, normalizeToolCalls } from "./ollama.mjs";
import { BurpMcp } from "./mcp.mjs";
import { toOllamaTools, isMeta, isRisky, validateArgs, schemaHint, hostInScope, META_TOOLS as META_TOOL_SCHEMAS } from "./tools.mjs";
import fs from "node:fs";
import path from "node:path";

const CTX_TRUNC = 2000; // keep per-tool context small for an 8b window

export class Agent {
  constructor({ mcp, store, model, target, scope = [], docsDir, onUserInput }) {
    this.mcp = mcp;
    this.store = store;
    this.model = model;
    this.target = target;
    this.scope = scope;
    this.docsDir = docsDir;
    this.onUserInput = onUserInput; // async (promptText) => string
    this.messages = [];
    this.mcpTools = [];
    this.tools = [];
    this.gateRisky = true;
    this.running = true;
  }

  async init() {
    this.mcpTools = await this.mcp.listTools();
    this.tools = toOllamaTools(this.mcpTools);
    this._schemas = Object.fromEntries(this.mcpTools.map((t) => [t.name, t.inputSchema ?? {}]));
    for (const t of META_TOOL_SCHEMAS) this._schemas[t.name] = t.parameters;
  }

  systemPrompt() {
    return [
      "You are the pilot of a semi-autonomous bug-bounty agent. You direct Burp Suite through its MCP tools to recon, scan, intercept, and replay.",
      `TARGET: ${this.target || "(none set yet - ask the operator)"}`,
      `SCOPE: ${this.scope.length ? this.scope.join(", ") : "(not set - all hosts allowed; suggest the operator set one)"}`,
      "",
      "How to operate:",
      "- Prefer read-only recon first (get_proxy_http_history, get_organizer_items, output_project_options) to understand state before sending traffic.",
      "- Take one focused action per turn. Keep reasoning short.",
      "- When you need a decision, the target, or to hand off, call ask_user().",
      "- As you learn things that matter later, call remember() to record them.",
      "- Consult reference notes with list_docs() / read_doc(name).",
      "- Search long-term memory with recall(query) before repeating past work or when context is missing.",
      "- When the objective is met, call finish(summary) so the run can stop.",
      "- If you're blocked or unsure, say so in plain text instead of guessing.",
      "",
      "Accuracy rules (strict):",
      "- ONLY call tools from the provided list. Never invent tool names or arguments.",
      "- Match each tool's schema exactly: required fields, value types, allowed enum values.",
      "- Never fabricate results. If you didn't call a tool, you don't know the answer - call it or ask_user().",
      "- If a tool call errors, read the error, correct the arguments, and retry DIFFERENTLY. Never repeat an identical failed call.",
      "- Base conclusions only on actual tool output. Quote the evidence in remember() and finish().",
      "- Never send traffic to a host outside SCOPE. If a host seems relevant but out of scope, ask_user() instead.",
      "- When crafting raw HTTP requests (send_http1_request, repeater tabs): always include a Host header and end the headers with a blank line.",
    ].join("\n");
  }

  // Full prompt = static rules + fresh long-term memory tail (so recall improves as we learn).
  systemPromptWithMemory() {
    const mem = this.store.learningsTail(2500);
    return this.systemPrompt() + (mem ? "\n\nLong-term memory (from previous sessions):\n" + mem : "");
  }

  addInstruction(text) {
    this.messages.push({ role: "user", content: text });
    this.store.user(text);
  }

  // Keep acting while the model keeps issuing tool calls; stop on finish/ask_user/prose
  // or when maxSteps is hit (safety cap so a runaway loop can't run forever).
  async runBurst({ onStep, maxSteps = 25 } = {}) {
    let n = 0;
    while (this.running && n < maxSteps) {
      const s = await this._step();
      onStep?.(s);
      n++;
      if (s.stopReason === "finish") break;
      if (s.stopReason === "ask_user") break;
      if (s.stopReason === "repeat") break; // loop detected -> hand back to operator
      if (s.stopReason === "prose") break; // model has something to say -> hand back to operator
      if (!this.running) break;
    }
    return { steps: n };
  }
  async _step() {
    const messages = [{ role: "system", content: this.systemPromptWithMemory() }, ...this.messages];
    // temperature 0 + fixed seed = deterministic output for a given context.
    const msg = await chat({ model: this.model, messages, tools: this.tools, temperature: 0, numCtx: 8192, options: { seed: 42 } });
    const calls = normalizeToolCalls(msg);

    // Record the assistant turn (raw tool_calls keep Ollama's object-arg shape).
    this.messages.push({ role: "assistant", content: msg.content || "", tool_calls: msg.tool_calls ?? [] });
    this.store.model(msg.content || "", calls.map((c) => ({ name: c.name, args: c.arguments })));

    if (!calls.length) {
      return { stopReason: "prose", content: msg.content || "", calls: [], results: [] };
    }

    // Repetition guard: 8b models can get stuck re-issuing an identical call.
    // Break the burst and hand back to the operator on the 3rd repeat.
    const sig = calls.map((c) => c.name + " " + JSON.stringify(c.arguments ?? {})).join("|");
    if (sig === this._lastSig) this._repeatCount = (this._repeatCount ?? 0) + 1;
    else { this._repeatCount = 0; this._lastSig = sig; }
    if (this._repeatCount >= 2) {
      const note = `repeated identical tool call(s) 3x: ${sig.slice(0, 200)} - burst stopped for operator review`;
      this.store.handoff(note);
      return { stopReason: "repeat", content: note, calls, results: [] };
    }

    const results = [];
    for (const call of calls) {
      const name = String(call.name || "").trim();
      let args = call.arguments || {};
      if (isMeta(name)) {
        results.push({ name, meta: true, ...(await this._meta(name, args)) });
        continue;
      }
      // Unknown-tool guard: correct the model instead of executing nothing/crashing.
      if (!this._schemas[name]) {
        const text = `error: unknown tool "${name}". Only call tools from the provided list, with matching names.`;
        this.store.tool(name, args, text, true);
        results.push({ name, text, isError: true });
        this.messages.push({ role: "tool", content: text });
        continue;
      }
      // Arg validation: coerce what we safely can; reject with a precise schema hint otherwise.
      const v = validateArgs(this._schemas[name], args);
      if (!v.ok) {
        const text = `error: invalid arguments for "${name}": ${v.errors.join("; ")}. Schema: ${schemaHint(name, this._schemas[name])}. Retry with corrected arguments.`;
        this.store.tool(name, args, text, true);
        results.push({ name, text, isError: true });
        this.messages.push({ role: "tool", content: text });
        continue;
      }
      args = v.args; // coerced
      // Scope guard: hard-block traffic to out-of-scope hosts (before the gate).
      if (this.scope.length && typeof args.targetHostname === "string" && !hostInScope(args.targetHostname, this.scope)) {
        const text = `error: "${args.targetHostname}" is outside the engagement scope (${this.scope.join(", ")}). Do not send traffic there; ask_user() if you believe it should be in scope.`;
        this.store.tool(name, args, text, true);
        this.store.handoff(`SCOPE BLOCK: ${name} -> ${args.targetHostname}`);
        results.push({ name, text, isError: true, blocked: true });
        this.messages.push({ role: "tool", content: text });
        continue;
      }
      // Human gate on risky Burp actions.
      if (isRisky(name) && this.gateRisky) {
        const ok = await this.onUserInput(`[GATE] allow risky tool "${name}" ${JSON.stringify(args)} ? (y/n)`);
        if (!/^y(es)?$/i.test((ok || "").trim())) {
          this.store.tool(name, args, "(operator declined)", true);
          results.push({ name, text: "(operator declined)", isError: true, declined: true });
          this.messages.push({ role: "tool", content: "(operator declined that action)" });
          continue;
        }
      }
      let text, isError = false;
      try {
        const r = await this.mcp.callTool(name, args);
        text = BurpMcp.toolText(r) || JSON.stringify(r);
        isError = !!r?.isError;
      } catch (e) { text = "error: " + e.message; isError = true; }
      this.store.tool(name, args, text, isError);
      results.push({ name, text, isError });
      this.messages.push({ role: "tool", content: truncate(text, CTX_TRUNC) });
    }

    const ask = results.find((r) => r.name === "ask_user");
    if (ask) return { stopReason: "ask_user", content: msg.content || "", calls, results };
    const fin = results.find((r) => r.name === "finish");
    if (fin) return { stopReason: "finish", content: fin.summary || msg.content || "", calls, results };
    return { stopReason: "tools", content: msg.content || "", calls, results };
  }

  async _meta(name, args) {
    switch (name) {
      case "ask_user": {
        const q = args?.question || "(question)";
        const a = await this.onUserInput(q);
        this.store.handoff("ask_user Q: " + q + "  A: " + (a || "(empty)"));
        this.messages.push({ role: "tool", content: "Operator answered: " + (a || "(empty)") });
        return { question: q, answer: a, text: "Operator answered: " + (a || "(empty)") };
      }
      case "remember": {
        const note = args?.note || "";
        this.store.remember(note);
        this.store.handoff("remember: " + note);
        this.messages.push({ role: "tool", content: "remembered." });
        return { note, text: "remembered." };
      }
      case "recall": {
        const t = this.store.searchMemory(args?.query);
        this.messages.push({ role: "tool", content: truncate(t, CTX_TRUNC) });
        return { text: t };
      }
      case "list_docs": {
        const t = this._listDocs();
        this.messages.push({ role: "tool", content: t });
        return { text: t };
      }
      case "read_doc": {
        const t = this._readDoc(args?.name);
        this.messages.push({ role: "tool", content: t });
        return { text: t };
      }
      case "finish": {
        this.messages.push({ role: "tool", content: "finished." });
        return { summary: args?.summary || "", text: "finished." };
      }
      default: {
        this.messages.push({ role: "tool", content: "unknown meta tool: " + name });
        return { text: "unknown meta tool: " + name };
      }
    }
  }

  _listDocs() {
    try {
      const files = fs.readdirSync(this.docsDir).filter((f) => /\.(md|txt)$/i.test(f));
      return files.length ? files.join("\n") : "(no docs in docs/ yet)";
    } catch { return "(no docs/ dir)"; }
  }
  _readDoc(name) {
    if (!name) return "read_doc: missing name";
    const safe = path.basename(String(name));
    for (const cand of [safe, safe + ".md", safe + ".txt"]) {
      const p = path.join(this.docsDir, cand);
      if (fs.existsSync(p)) return fs.readFileSync(p, "utf8").slice(0, 8000);
    }
    return "doc not found: " + name;
  }
}

function truncate(s, n) { s = String(s ?? ""); return s.length > n ? s.slice(0, n) + " …(truncated)" : s; }

