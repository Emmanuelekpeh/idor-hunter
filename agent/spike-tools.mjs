#!/usr/bin/env node
// agent/spike-tools.mjs
// De-risk before building the agent: can granite4.1:8b (a) pick a Burp MCP tool
// via Ollama structured tool-calling, and (b) can we execute that chosen tool
// against Burp's SSE MCP server end-to-end? Zero deps, Node >= 18.
const OLLAMA = process.env.OLLAMA_URL || "http://127.0.0.1:11434";
const MODEL = process.env.OLLAMA_MODEL || "granite4.1:8b";
const BURP = process.env.BURP_MCP_URL || "http://127.0.0.1:9876";
const log = (...a) => console.log(...a);

// ---- Ollama native /api/chat with tools ----
async function ollamaChat(messages, tools) {
  const r = await fetch(`${OLLAMA}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: MODEL, messages, tools, stream: false, options: { temperature: 0, num_ctx: 8192 } }),
    signal: AbortSignal.timeout(120000),
  });
  if (!r.ok) throw new Error("Ollama " + r.status + ": " + (await r.text()).slice(0, 300));
  return (await r.json()).message;
}

// ---- minimal SSE MCP client ----
function sseParse(raw) {
  const buf = raw.replace(/\r\n/g, "\n"); // Java/SSE servers emit CRLF
  const events = [];
  let idx;
  let rem = buf;
  while ((idx = rem.indexOf("\n\n")) !== -1) {
    const rawEvent = rem.slice(0, idx);
    rem = rem.slice(idx + 2);
    let event = "message";
    const data = [];
    for (const line of rawEvent.split("\n")) {
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
    }
    events.push({ event, data: data.join("\n") });
  }
  return { events, rem };
}

const mcp = { res: null, reader: null, dec: new TextDecoder(), buf: "", post: null, responses: {} };

async function rpc(id, method, params) {
  const r = await fetch(mcp.post, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params: params ?? {} }),
    signal: AbortSignal.timeout(15000),
  });
  return r.status;
}

async function mcpWaitResponse(id, timeoutMs = 8000) {
  const dl = Date.now() + timeoutMs;
  while (!mcp.responses[id] && Date.now() < dl) {
    const { value, done } = await mcp.reader.read();
    if (done) break;
    mcp.buf += mcp.dec.decode(value, { stream: true });
    const p = sseParse(mcp.buf);
    mcp.buf = p.rem;
    for (const e of p.events) {
      if (e.event === "message" && e.data) {
        let m; try { m = JSON.parse(e.data); } catch { continue; }
        if (m && m.id !== undefined && (m.result !== undefined || m.error !== undefined)) mcp.responses[m.id] = m;
      }
    }
  }
  return mcp.responses[id];
}

async function mcpConnect() {
  mcp.res = await fetch(`${BURP}/`, { headers: { "Accept": "text/event-stream" }, signal: AbortSignal.timeout(30000) });
  const ct = mcp.res.headers.get("content-type") || "";
  if (!mcp.res.ok || !ct.includes("text/event-stream")) throw new Error("SSE open failed: " + mcp.res.status + " " + ct);
  mcp.reader = mcp.res.body.getReader();
  let ep = null;
  const dl = Date.now() + 5000;
  while (!ep && Date.now() < dl) {
    const { value, done } = await mcp.reader.read();
    if (done) throw new Error("SSE ended before endpoint");
    mcp.buf += mcp.dec.decode(value, { stream: true });
    const p = sseParse(mcp.buf);
    mcp.buf = p.rem;
    for (const e of p.events) if (e.event === "endpoint") ep = e.data.trim();
  }
  if (!ep) throw new Error("no endpoint event");
  mcp.post = ep.startsWith("http") ? ep : `${BURP}/${ep.replace(/^\/+/, "")}`;
  await rpc(1, "initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "spike", version: "1.0.0" } });
  const initRes = await mcpWaitResponse(1, 8000);
  if (initRes?.error) throw new Error("initialize failed: " + JSON.stringify(initRes.error));
  await fetch(mcp.post, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) }).catch(() => {});
  log("Burp MCP connected: " + (initRes?.result?.serverInfo?.name ?? "?"));
}
const tools = [
  { type: "function", function: { name: "get_proxy_http_history", description: "Displays items within the proxy HTTP history", parameters: { type: "object", properties: { count: { type: "integer", description: "number of items to return" }, offset: { type: "integer", description: "start offset" } }, required: ["count", "offset"] } } },
  { type: "function", function: { name: "get_organizer_items", description: "Displays items within the Organizer tab", parameters: { type: "object", properties: { count: { type: "integer" }, offset: { type: "integer" } }, required: ["count", "offset"] } } },
  { type: "function", function: { name: "url_encode", description: "URL encodes the input string", parameters: { type: "object", properties: { content: { type: "string" } }, required: ["content"] } } },
];

(async () => {
  log("== 1. Ollama tool-calling spike (" + MODEL + ") ==");
  const msg = await ollamaChat([
    { role: "system", content: "You are a bug-bounty helper. Act on Burp Suite using the provided tools. Prefer concrete tool calls over prose." },
    { role: "user", content: "Target: https://example.test . 1) Show the last 3 proxy HTTP history items. 2) URL-encode the string: a b&c" },
  ], tools);

  log("\n-- model content: " + JSON.stringify(msg.content));
  const calls = (msg.tool_calls || []).map((tc) => tc.function ?? tc);
  log("-- tool_calls (" + calls.length + "):");
  for (const c of calls) log("   * " + c.name + "  " + (typeof c.arguments === "object" ? JSON.stringify(c.arguments) : String(c.arguments)));
  if (!calls.length) { log("\nWRN  No tool calls returned; 8b needs steering or a stronger model."); process.exit(2); }

  log("\n== 2. Execute the chosen tool against Burp MCP ==");
  await mcpConnect();
  const first = calls[0];
  let args = first.arguments;
  if (typeof args === "string") { try { args = JSON.parse(args); } catch { args = {}; } }
  const status = await rpc(3, "tools/call", { name: first.name, arguments: args });
  log("tools/call POST -> " + status + "   (" + first.name + " " + JSON.stringify(args) + ")");
  const res = await mcpWaitResponse(3, 10000);
  if (res?.error) log("tool error: " + JSON.stringify(res.error));
  else if (res?.result) {
    log("\n-- Burp tool result:");
    const s = JSON.stringify(res.result);
    log(s.length > 1400 ? s.slice(0, 1400) + " ... (truncated)" : s);
  } else {
    log("no result captured (ids seen: " + Object.keys(mcp.responses).join(", ") + ")");
  }
  try { await mcp.res.body.cancel(); } catch {}
  log("\nOK  END-TO-END: 8b chose a tool and Burp executed it.");
  process.exit(0);
})().catch((e) => { log("\nERR  spike: " + e.message); process.exit(1); });

