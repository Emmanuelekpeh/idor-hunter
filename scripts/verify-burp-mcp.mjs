#!/usr/bin/env node
// verify-burp-mcp.mjs
// Dependency-free (Node >= 18, built-in fetch + streams) end-to-end check of the
// Kilo -> Ollama(8b) -> Burp MCP chain. No npm install required.
//
//   1. Ollama: is it reachable, and is the target 8b model present?
//   2. Ollama smoke test: does the model actually generate (one tiny completion)?
//   3. Burp MCP: perform the legacy SSE handshake (GET stream -> endpoint ->
//      POST initialize -> tools/list) and print the discovered tools.
//
// Env overrides:
//   OLLAMA_URL     (default http://127.0.0.1:11434)
//   OLLAMA_MODEL   (default granite4.1:8b)
//   BURP_MCP_URL   (default http://127.0.0.1:9876)

const OLLAMA_URL = process.env.OLLAMA_URL || "http://127.0.0.1:11434";
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || "granite4.1:8b";
const BURP_MCP_URL = process.env.BURP_MCP_URL || "http://127.0.0.1:9876";

const banner = (t) => console.log("\n" + "=".repeat(64) + "\n" + t + "\n" + "=".repeat(64));
const ok = (s) => console.log("\u2705 " + s);
const warn = (s) => console.log("\u26A0\uFE0F  " + s);
const fail = (s) => console.log("\u274C " + s);

// 1. Ollama reachable + model present
async function checkOllama() {
  banner("1. Ollama");
  console.log(`endpoint: ${OLLAMA_URL}   target model: ${OLLAMA_MODEL}`);
  try {
    const r = await fetch(`${OLLAMA_URL}/api/tags`, { signal: AbortSignal.timeout(3000) });
    if (!r.ok) { warn(`Ollama responded but HTTP ${r.status}`); return { up: false, hasModel: false }; }
    const data = await r.json();
    const names = (data.models || []).map((m) => m.name);
    ok(`Ollama is UP. ${names.length} model(s) installed.`);
    const hasModel = names.some((n) => n === OLLAMA_MODEL || n.startsWith(OLLAMA_MODEL + ":"));
    if (hasModel) ok(`Target model "${OLLAMA_MODEL}" is available.`);
    else warn(`Target model "${OLLAMA_MODEL}" NOT found. Installed: ${names.join(", ") || "(none)"}`);
    return { up: true, hasModel, names };
  } catch (e) {
    fail(`Ollama not reachable at ${OLLAMA_URL}: ${e.message}`);
    return { up: false, hasModel: false };
  }
}

// 2. Ollama smoke test via OpenAI-compatible /v1
async function ollamaSmokeTest() {
  banner("2. Ollama model smoke test");
  const base = OLLAMA_URL.endsWith("/v1") ? OLLAMA_URL : OLLAMA_URL + "/v1";
  try {
    const r = await fetch(`${base}/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: OLLAMA_MODEL,
        messages: [{ role: "user", content: "Reply with exactly: PONG" }],
        stream: false,
        options: { num_predict: 32 },
      }),
      signal: AbortSignal.timeout(90000),
    });
    if (!r.ok) {
      const txt = await r.text().catch(() => "");
      warn(`/v1/chat/completions -> HTTP ${r.status}. ${txt.slice(0, 200)}`);
      return false;
    }
    const data = await r.json();
    const reply = data?.choices?.[0]?.message?.content?.trim?.() || "";
    console.log(`model reply: "${reply}"`);
    return true;
  } catch (e) {
    warn(`smoke test error: ${e.message}`);
    return false;
  }
}
// 3. Burp MCP legacy SSE handshake + tools/list
function makeSseParser(raw) {
  // Java/SSE servers often emit CRLF line endings; normalize to LF so that a
  // blank line ("\n\n") reliably delimits events.
  const buf = raw.replace(/\r\n/g, "\n");
  const events = [];
  let idx;
  let remaining = buf;
  while ((idx = remaining.indexOf("\n\n")) !== -1) {
    const rawEvent = remaining.slice(0, idx);
    remaining = remaining.slice(idx + 2);
    let event = "message";
    const dataLines = [];
    for (const line of rawEvent.split("\n")) {
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) dataLines.push(line.slice(5).replace(/^ /, ""));
    }
    events.push({ event, data: dataLines.join("\n") });
  }
  return { events, remaining };
}

async function checkBurpMcp() {
  banner("3. Burp MCP (SSE handshake + tools/list)");
  console.log(`endpoint: ${BURP_MCP_URL}`);
  let streamRes, reader, decoder, buf = "";
  try {
    streamRes = await fetch(`${BURP_MCP_URL}/`, {
      headers: { "Accept": "text/event-stream" },
      signal: AbortSignal.timeout(30000),
    });
    const ctype = streamRes.headers.get("content-type") || "";
    if (!streamRes.ok || !ctype.includes("text/event-stream")) {
      fail(`SSE stream open failed: HTTP ${streamRes.status} (${ctype})`);
      fail("Is Burp running with the MCP extension enabled on this host/port?");
      return false;
    }
    ok(`SSE stream opened (HTTP ${streamRes.status}).`);
    reader = streamRes.body.getReader();
    decoder = new TextDecoder();

    const readUntil = async (pred, timeoutMs) => {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        const { value, done } = await reader.read();
        if (done) return { hit: false, ev: null };
        buf += decoder.decode(value, { stream: true });
        const parsed = makeSseParser(buf);
        buf = parsed.remaining;
        for (const ev of parsed.events) if (pred(ev)) return { hit: true, ev };
      }
      return { hit: false, ev: null };
    };

    const ep = await readUntil((e) => e.event === "endpoint", 5000);
    if (!ep.hit) { fail("No 'endpoint' SSE event received."); return false; }
    const endpoint = ep.ev.data.trim();
    const postUrl = endpoint.startsWith("http")
      ? endpoint
      : `${BURP_MCP_URL}/${endpoint.replace(/^\/+/, "")}`;
    ok(`messages endpoint: ${postUrl}`);

    const responses = {};
    const noteMsg = (ev) => {
      if (ev.event !== "message" || !ev.data) return;
      let m; try { m = JSON.parse(ev.data); } catch { return; }
      if (m && m.id !== undefined && (m.result !== undefined || m.error !== undefined)) responses[m.id] = m;
    };

    const rpc = async (id, method, params) => {
      const body = JSON.stringify({ jsonrpc: "2.0", id, method, params: params ?? {} });
      const pr = await fetch(postUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json, text/event-stream" },
        body,
        signal: AbortSignal.timeout(10000),
      });
      return pr.status;
    };
    const s1 = await rpc(1, "initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "bounty-verify", version: "1.0.0" },
    });
    console.log(`initialize POST -> ${s1}`);

    await fetch(postUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    }).catch(() => {});

    const s3 = await rpc(3, "tools/list", {});
    console.log(`tools/list POST -> ${s3}`);

    const deadline = Date.now() + 8000;
    while (!responses[3] && Date.now() < deadline) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const parsed = makeSseParser(buf);
      buf = parsed.remaining;
      for (const ev of parsed.events) noteMsg(ev);
    }

    const init = responses[1];
    if (init?.result) ok(`MCP server: ${init.result.serverInfo?.name} (v${init.result.serverInfo?.version}), protocol ${init.result.protocolVersion}`);
    else if (init?.error) fail("initialize error: " + JSON.stringify(init.error));

    const toolsMsg = responses[3];
    if (toolsMsg?.result?.tools?.length) {
      const tools = toolsMsg.result.tools;
      ok(`Burp MCP tools discovered (${tools.length}):`);
      for (const t of tools) console.log("   - " + t.name + (t.description ? "  \u2014 " + t.description.replace(/\s+/g, " ").slice(0, 80) : ""));
      return true;
    }
    warn("Did not receive a tools/list result in time. ids: " + Object.keys(responses).join(", "));
    return false;
  } catch (e) {
    fail(`Burp MCP check failed: ${e.message}`);
    return false;
  } finally {
    try { reader?.releaseLock(); } catch {}
    try { await streamRes?.body?.cancel?.(); } catch {}
  }
}

(async () => {
  const ollama = await checkOllama();
  const burp = await checkBurpMcp();
  const smoke = ollama.up && ollama.hasModel ? await ollamaSmokeTest() : false;
  banner("RESULT");
  console.log(`Ollama reachable : ${ollama.up ? "OK" : "FAIL"}`);
  console.log(`8b model present : ${ollama.hasModel ? "OK (" + OLLAMA_MODEL + ")" : "MISSING"}`);
  console.log(`8b smoke test    : ${smoke ? "OK" : "skipped/failed"}`);
  console.log(`Burp MCP tools   : ${burp ? "OK" : "FAIL"}`);
  const go = ollama.up && ollama.hasModel && burp;
  console.log(`\n${go ? "\u2705 GO \u2014 Kilo + Ollama(" + OLLAMA_MODEL + ") + Burp MCP chain is ready." : "\u26A0\uFE0F  NOT READY \u2014 fix the FAIL items above, then re-run."}`);
  process.exit(go ? 0 : 2);
})();


