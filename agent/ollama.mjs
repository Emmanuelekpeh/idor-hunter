// agent/ollama.mjs
// Minimal Ollama client using the NATIVE /api/chat endpoint (best structured
// tool-calling support for small local models). No deps; Node >= 18.
const OLLAMA = process.env.OLLAMA_URL || "http://127.0.0.1:11434";

/**
 * Run a chat completion (non-streaming) with optional tool schemas.
 * @param {object} o { model, messages, tools, temperature, numCtx, options, timeoutMs }
 * @returns {Promise<{role:string, content:string, tool_calls?:Array}>}
 */
export async function chat({ model, messages, tools, temperature = 0, numCtx = 8192, options = {}, timeoutMs = 600000 }) {
  const body = { model, messages, stream: false, options: { temperature, num_ctx: numCtx, ...options } };
  if (tools && tools.length) body.tools = tools;
  const r = await fetch(`${OLLAMA}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!r.ok) throw new Error("Ollama /api/chat " + r.status + ": " + (await r.text().catch(() => "")).slice(0, 300));
  const data = await r.json();
  return data.message ?? { role: "assistant", content: "", tool_calls: [] };
}

/**
 * Normalize Ollama tool_calls: {function:{name,arguments}} (args may be object or JSON string).
 * @returns {Array<{name:string, arguments:object}>}
 */
export function normalizeToolCalls(message) {
  return (message?.tool_calls ?? []).map((tc) => {
    const f = tc.function ?? tc;
    let args = f.arguments ?? {};
    if (typeof args === "string") { try { args = JSON.parse(args); } catch { args = { _raw: args }; } }
    return { name: f.name, arguments: args };
  });
}

/** Build the assistant message + tool-response message pair to continue a turn. */
export function toolTurn(assistantMsg, toolResponses) {
  // assistantMsg: raw Ollama message (has tool_calls). toolResponses: [{name, content, isError}]
  const out = [{ role: "assistant", content: assistantMsg.content || "", tool_calls: assistantMsg.tool_calls ?? [] }];
  for (const tr of toolResponses) out.push({ role: "tool", content: tr.content });
  return out;
}

export async function listModels() {
  const r = await fetch(`${OLLAMA}/api/tags`, { signal: AbortSignal.timeout(5000) });
  if (!r.ok) throw new Error("Ollama not reachable (" + r.status + ") at " + OLLAMA);
  const d = await r.json();
  return (d.models ?? []).map((m) => m.name);
}
