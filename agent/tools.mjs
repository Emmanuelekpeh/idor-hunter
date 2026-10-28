// agent/tools.mjs
// Meta-tools the model can call to control flow / interject / persist, plus helpers
// to fold the live Burp MCP tools into the Ollama `tools` payload.
export const META_TOOLS = [
  { name: "ask_user", description: "Ask the operator a question and WAIT for their answer before proceeding. Use when you need a decision, a target, or missing detail.", parameters: { type: "object", properties: { question: { type: "string" } }, required: ["question"] } },
  { name: "remember", description: "Record a durable note, finding, or handoff into long-term memory for this engagement.", parameters: { type: "object", properties: { note: { type: "string" } }, required: ["note"] } },
  { name: "recall", description: "Search long-term memory (learnings log + past session transcripts) for a keyword or phrase. Use at the start of a session and before repeating past work.", parameters: { type: "object", properties: { query: { type: "string" } }, required: ["query"] } },
  { name: "list_docs", description: "List reference documents available in the docs/ folder.", parameters: { type: "object", properties: {}, required: [] } },
  { name: "read_doc", description: "Read a reference document from docs/ by name or filename.", parameters: { type: "object", properties: { name: { type: "string" } }, required: ["name"] } },
  { name: "finish", description: "Signal that the current objective is complete and provide a summary of findings.", parameters: { type: "object", properties: { summary: { type: "string" } }, required: ["summary"] } },
];

export function isMeta(name) { return META_TOOLS.some((t) => t.name === name); }

// Scope check: exact host ("example.com", "localhost") or wildcard ("*.example.com"
// matches the apex and any subdomain). Empty scope = everything allowed.
export function hostInScope(hostname, scope) {
  if (!scope || !scope.length) return true;
  const h = String(hostname || "").toLowerCase().trim();
  if (!h) return false;
  for (const p of scope) {
    const pat = String(p).toLowerCase().trim();
    if (!pat) continue;
    if (pat.startsWith("*.")) { const apex = pat.slice(2); if (h === apex || h.endsWith("." + apex)) return true; }
    else if (h === pat) return true;
  }
  return false;
}

// --- Accuracy guards -------------------------------------------------------

// Validate + coerce model-supplied args against an MCP inputSchema.
// 8b models commonly send numbers as strings, wrong casing on booleans, or drop
// required fields — fix what's safely fixable, report the rest precisely.
// Returns { ok, args (coerced), errors[] }.
export function validateArgs(schema, rawArgs) {
  const errors = [];
  const out = {};
  const args = rawArgs && typeof rawArgs === "object" ? rawArgs : {};
  const props = schema?.properties ?? {};
  const required = schema?.required ?? [];
  for (const [k, v] of Object.entries(args)) {
    const spec = props[k];
    if (!spec) {
      // Unknown arg: drop it if the schema is closed, otherwise pass through.
      if (Object.keys(props).length && schema?.additionalProperties === false) continue;
      out[k] = v;
      continue;
    }
    const t = Array.isArray(spec.type) ? spec.type.find((x) => x !== "null") : spec.type;
    let val = v;
    if (t === "integer" || t === "number") {
      if (typeof val === "string" && val.trim() !== "" && !isNaN(Number(val))) val = Number(val);
      if (typeof val !== "number" || Number.isNaN(val)) { errors.push(`${k}: expected ${t}, got ${JSON.stringify(v)}`); continue; }
      if (t === "integer" && !Number.isInteger(val)) val = Math.trunc(val);
    } else if (t === "boolean") {
      if (typeof val === "string") {
        if (/^(true|1)$/i.test(val)) val = true;
        else if (/^(false|0)$/i.test(val)) val = false;
      }
      if (typeof val !== "boolean") { errors.push(`${k}: expected boolean, got ${JSON.stringify(v)}`); continue; }
    } else if (t === "string") {
      if (typeof val !== "string") val = String(val);
    }
    if (spec.enum && !spec.enum.includes(val)) { errors.push(`${k}: must be one of ${JSON.stringify(spec.enum)}, got ${JSON.stringify(val)}`); continue; }
    out[k] = val;
  }
  for (const r of required) if (!(r in out)) errors.push(`missing required arg "${r}"`);
  return { ok: errors.length === 0, args: out, errors };
}

// Compact one-line schema summary used in corrective feedback to the model.
export function schemaHint(name, schema) {
  const props = schema?.properties ?? {};
  const req = new Set(schema?.required ?? []);
  const parts = Object.entries(props).map(([k, s]) => {
    const t = Array.isArray(s.type) ? s.type.join("|") : s.type ?? "any";
    return `${k}${req.has(k) ? "*" : ""}:${t}${s.enum ? " " + JSON.stringify(s.enum) : ""}`;
  });
  return `${name}(${parts.join(", ")})  (* = required)`;
}

// Burp actions that mutate state or send traffic -> gated behind the operator.
const RISKY = new Set([
  "set_proxy_intercept_state", "send_http1_request", "send_http2_request",
  "create_repeater_tab", "create_repeater_tab_http2", "send_to_intruder",
  "set_task_execution_engine_state", "set_project_options", "set_user_options", "set_active_editor_contents",
]);
export function isRisky(name) { return RISKY.has(name); }

// Convert MCP tool defs ({name, description, inputSchema}) + meta tools into the
// Ollama `tools` array shape.
export function toOllamaTools(mcpTools) {
  const mcp = (mcpTools ?? []).map((t) => ({
    type: "function",
    function: {
      name: t.name,
      description: t.description || "",
      parameters: t.inputSchema && Object.keys(t.inputSchema).length ? t.inputSchema : { type: "object", properties: {} },
    },
  }));
  const meta = META_TOOLS.map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.parameters } }));
  return [...mcp, ...meta];
}
