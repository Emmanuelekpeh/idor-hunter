// agent/mcp.mjs
// Burp Suite MCP client over the SSE transport. Runs a persistent SSE stream for
// the life of the session and dispatches JSON-RPC responses by id. No deps.
export class BurpMcp {
  constructor(url = process.env.BURP_MCP_URL || "http://127.0.0.1:9876") {
    this.url = url;
    this.dec = new TextDecoder();
    this.buf = "";
    this.reader = null;
    this.res = null;
    this.post = null;
    this.serverInfo = null;
    this.tools = [];
    this._id = 0;
    this._pending = new Map();
    this._endpointResolve = null;
    this._running = false;
  }

  _sseParse(raw) {
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

  _readerLoop() {
    this._running = true;
    (async () => {
      while (this._running) {
        let value, done;
        try { ({ value, done } = await this.reader.read()); } catch { break; }
        if (done) break;
        this.buf += this.dec.decode(value, { stream: true });
        const { events, rem } = this._sseParse(this.buf);
        this.buf = rem;
        for (const e of events) {
          if (e.event === "endpoint" && !this.post) {
            const d = e.data.trim();
            this.post = d.startsWith("http") ? d : `${this.url}/${d.replace(/^\/+/, "")}`;
            if (this._endpointResolve) this._endpointResolve();
          } else if (e.event === "message" && e.data) {
            let m;
            try { m = JSON.parse(e.data); } catch { continue; }
            if (m && m.id !== undefined) {
              const cb = this._pending.get(m.id);
              if (cb) { this._pending.delete(m.id); cb(m); }
            }
          }
        }
      }
    })();
  }

  async connect() {
    this.res = await fetch(`${this.url}/`, { headers: { "Accept": "text/event-stream" }, signal: AbortSignal.timeout(30000) });
    const ct = this.res.headers.get("content-type") || "";
    if (!this.res.ok || !ct.includes("text/event-stream")) throw new Error("Burp SSE open failed: HTTP " + this.res.status + " (" + ct + ")");
    this.reader = this.res.body.getReader();
    this._readerLoop();
    await new Promise((res, rej) => { this._endpointResolve = res; setTimeout(() => rej(new Error("no endpoint event within 6s")), 6000); });
    const init = await this._rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "bounty-agent", version: "1.0.0" } });
    if (init?.error) throw new Error("initialize failed: " + JSON.stringify(init.error));
    this.serverInfo = init?.result?.serverInfo ?? null;
    await this._notify("notifications/initialized");
    return this.serverInfo;
  }

  // NOTE: Burp's MCP server may hold the POST open until the tool finishes
  // executing, so the POST timeout must track the RPC timeout, not a fixed 20s.
  async _post(bodyObj, timeoutMs = 30000) {
    const r = await fetch(this.post, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json, text/event-stream" },
      body: JSON.stringify(bodyObj),
      signal: AbortSignal.timeout(timeoutMs),
    });
    return r.status;
  }
  async _notify(method) { await this._post({ jsonrpc: "2.0", method }); }
  async _rpc(method, params, timeoutMs = 30000) {
    const id = ++this._id;
    const p = new Promise((res) => this._pending.set(id, res));
    await this._post({ jsonrpc: "2.0", id, method, params: params ?? {} }, timeoutMs + 10000);
    return await Promise.race([
      p,
      new Promise((_, rej) => setTimeout(() => rej(new Error("timeout waiting for " + method)), timeoutMs)),
    ]);
  }

  async listTools() {
    const r = await this._rpc("tools/list");
    this.tools = r?.result?.tools ?? [];
    return this.tools;
  }
  async callTool(name, args) {
    const r = await this._rpc("tools/call", { name, arguments: args ?? {} }, 90000);
    return r?.result ?? r;
  }
  static toolText(result) {
    return (result?.content ?? []).filter((c) => c.type === "text").map((c) => c.text).join("\n");
  }
  async close() { this._running = false; try { await this.res?.body?.cancel(); } catch {} }
}
