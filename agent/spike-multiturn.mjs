#!/usr/bin/env node
// agent/spike-multiturn.mjs
// Verify Ollama (this version) handles the multi-turn tool loop:
//   turn1 -> assistant tool_call ; append role:tool result ; turn2 -> next tool_call
import { chat, normalizeToolCalls, toolTurn } from "./ollama.mjs";
const MODEL = process.env.OLLAMA_MODEL || "granite4.1:8b";
const log = (...a) => console.log(...a);

const tools = [
  { type: "function", function: { name: "get_proxy_http_history", description: "Displays items within the proxy HTTP history", parameters: { type: "object", properties: { count: { type: "integer" }, offset: { type: "integer" } }, required: ["count", "offset"] } } },
  { type: "function", function: { name: "url_encode", description: "URL encodes the input string", parameters: { type: "object", properties: { content: { type: "string" } }, required: ["content"] } } },
];

(async () => {
  const messages = [
    { role: "system", content: "Bug-bounty helper. Use tools to act on Burp." },
    { role: "user", content: "Get the last 2 proxy HTTP history items." },
  ];

  log("== turn 1 ==");
  const m1 = await chat({ model: MODEL, messages, tools, temperature: 0, numCtx: 8192 });
  const c1 = normalizeToolCalls(m1);
  log("content: " + JSON.stringify(m1.content));
  log("tool_calls: " + JSON.stringify(c1));
  if (!c1.length) { log("WRN no tool call on turn 1"); process.exit(2); }

  // Append assistant tool_call + a synthetic tool result, then ask for a 2nd tool.
  const toolResult = "(result) 2 items: [GET https://example.test/ HTTP/1.1], [GET https://example.test/admin HTTP/1.1]";
  const cont = toolTurn(m1, [{ name: c1[0].name, content: toolResult }]);
  const messages2 = [...messages, ...cont, { role: "user", content: "Now URL-encode this: a b&c" }];

  log("\n== turn 2 ==");
  const m2 = await chat({ model: MODEL, messages: messages2, tools, temperature: 0, numCtx: 8192 });
  const c2 = normalizeToolCalls(m2);
  log("content: " + JSON.stringify(m2.content));
  log("tool_calls: " + JSON.stringify(c2));

  const gotUrlEncode = c2.some((c) => c.name === "url_encode" && c.arguments?.content === "a b&c");
  log("\n" + (gotUrlEncode ? "OK  multi-turn tool loop works; model followed the context." : "WRN  multi-turn did not yield url_encode as expected; message format may need adjusting."));
  process.exit(gotUrlEncode ? 0 : 2);
})().catch((e) => { log("ERR " + e.message); process.exit(1); });
