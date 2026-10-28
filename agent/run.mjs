// agent/run.mjs
// Bare REPL: you type, the agent works in bursts, you interject.
//   node agent/run.mjs [--target https://example.com] [--model granite4.1:8b]
//
// While the agent is mid-burst you stay in the loop via:
//   - [GATE] prompts before any risky Burp action (intercept/replay/engine/options)
//   - ask_user() questions from the model itself
// Commands (prefix with /):
//   /target <url>     set/switch the engagement target
//   /burst <n>        max steps per burst (default 25)
//   /gate on|off      toggle human approval for risky tools (default on)
//   /tools            list available Burp MCP + meta tools
//   /tool <name> <json>  call a Burp tool directly, bypassing the model
//   /status           session stats + memory file locations
//   /memory           show recent session events (handoffs, tool calls)
//   /docs             list reference docs the agent can read
//   /model <name>     switch Ollama model
//   /help             show this help
//   /quit             close Burp MCP stream and exit
// Anything else = an instruction/steering message to the agent, then it runs a burst.
import readline from "node:readline";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BurpMcp } from "./mcp.mjs";
import { Agent } from "./agent.mjs";
import { Store } from "./store.mjs";
import { listModels } from "./ollama.mjs";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

const argv = process.argv.slice(2);
function argVal(flag, dflt) { const i = argv.indexOf(flag); return i !== -1 ? argv[i + 1] : dflt; }
const MODEL = argVal("--model", process.env.BOUNTY_MODEL || "granite4.1:8b");
const TARGET = argVal("--target", process.env.BOUNTY_TARGET || "");
const SCOPE = (argVal("--scope", process.env.BOUNTY_SCOPE || "")).split(",").map((s) => s.trim()).filter(Boolean);
const GATE = !/^off$/i.test(argVal("--gate", "on"));

const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
let closed = false;
// Safe when stdin is gone (EOF/pipe end): gates default to deny, questions get an empty answer.
const ask = (q) => closed ? Promise.resolve("") : new Promise((res) => rl.question(q, (a) => res(a)));

// Queue lines from t=0 so input typed/piped during startup isn't lost.
const lineQueue = [];
let lineWaiter = null;
rl.on("line", (l) => { if (lineWaiter) { const w = lineWaiter; lineWaiter = null; w(l); } else lineQueue.push(l); });
rl.on("close", () => { closed = true; if (lineWaiter) { const w = lineWaiter; lineWaiter = null; w(null); } });
const nextLine = () => lineQueue.length ? Promise.resolve(lineQueue.shift())
  : closed ? Promise.resolve(null)
  : new Promise((res) => { lineWaiter = res; });

const store = new Store(ROOT);
const mcp = new BurpMcp();

let agent = null;
let burstMax = 25;

function onStep(s) {
  for (const r of s.results ?? []) {
    if (r.meta) {
      if (r.name === "remember") console.log(`  [remember] ${r.note}`);
      if (r.name === "finish") console.log(`  [finish] ${r.summary}`);
      continue;
    }
    const body = (r.text ?? "").replace(/\s+/g, " ").slice(0, 220);
    console.log(`  [tool] ${r.name}${r.isError ? " (error)" : ""}${r.declined ? " (declined)" : ""} -> ${body}`);
  }
  if (s.content) console.log(`  [agent] ${s.content}`);
}

async function runBurst() {
  console.log(`-- burst (max ${burstMax} steps, gates ${agent.gateRisky ? "ON" : "off"}) --`);
  const { steps } = await agent.runBurst({ onStep, maxSteps: burstMax });
  console.log(`-- burst ended after ${steps} step(s) --`);
}

async function main() {
  console.log("bounty agent REPL — bare, offline, Burp MCP + Ollama");
  try {
    const models = await listModels().catch(() => []);
    if (models.length && !models.some((m) => m.startsWith(MODEL))) {
      console.log(`!! model "${MODEL}" not in Ollama. Available: ${models.join(", ")}`);
    }
  } catch { console.log("!! Ollama not reachable at " + (process.env.OLLAMA_URL || "http://127.0.0.1:11434")); }

  console.log("connecting to Burp MCP at " + mcp.url + " ...");
  const info = await mcp.connect();
  console.log("connected:", info?.name ?? "burp", info?.version ?? "");

  agent = new Agent({
    mcp, store, model: MODEL, target: TARGET, scope: [...SCOPE],
    docsDir: path.join(ROOT, "docs"),
    onUserInput: async (q) => {
      if (closed) { console.log(`\n?? ${q}\n> (no operator - defaulting to safe answer)`); return ""; }
      return await ask(`\n?? ${q}\n> `);
    },
  });
  await agent.init();
  agent.gateRisky = GATE;
  console.log(`${agent.mcpTools.length} Burp tools + meta tools loaded. Session memory: ${store.file}`);
  if (TARGET) console.log("target: " + TARGET);
  console.log("scope: " + (SCOPE.length ? SCOPE.join(", ") : "(unset - all hosts allowed)") + "  |  gates: " + (GATE ? "ON" : "OFF"));
  console.log('type /help for commands, or just talk.\n');

  rl.setPrompt("bounty> ");
  rl.prompt();

  let line;
  while ((line = await nextLine()) !== null) {
    const input = line.trim();
    if (!input) { rl.prompt(); continue; }

    try {
      if (input.startsWith("/")) {
        const [cmd, ...rest] = input.slice(1).split(/\s+/);
        const arg = rest.join(" ");
        switch (cmd) {
          case "quit": case "exit": await shutdown(0); break;
          case "help":
            console.log([
              "/target <url>   set target      /burst <n>    steps per burst",
              "/scope <hosts>  scope allowlist  /gate on|off  risky-tool gates",
              "/tools          list tools       /tool <n> <json> direct Burp call",
              "/status         session stats    /memory       recent events",
              "/docs           list docs        /model <name> switch model",
              "/quit           exit",
              "anything else = steer the agent, then it runs a burst",
            ].join("\n"));
            break;
          case "target": agent.target = arg; store.handoff("target set: " + arg); console.log("target = " + arg); break;
          case "scope":
            if (arg) { agent.scope = arg.split(",").map((s) => s.trim()).filter(Boolean); store.handoff("scope set: " + agent.scope.join(", ")); }
            console.log("scope = " + (agent.scope.length ? agent.scope.join(", ") : "(unset - all hosts allowed)"));
            break;
          case "burst": burstMax = Math.max(1, parseInt(arg, 10) || 25); console.log("burst max = " + burstMax); break;
          case "gate": agent.gateRisky = !/^off$/i.test(arg); console.log("gates " + (agent.gateRisky ? "ON" : "OFF")); break;
          case "model": agent.model = arg; console.log("model = " + arg); break;
          case "tools":
            for (const t of agent.tools) console.log("  " + t.function.name + " — " + (t.function.description || "").split("\n")[0].slice(0, 80));
            break;
          case "docs": console.log(agent._listDocs()); break;
          case "tool": {
            const sp = arg.indexOf(" ");
            const name = sp === -1 ? arg : arg.slice(0, sp);
            let args = {};
            if (sp !== -1) { try { args = JSON.parse(arg.slice(sp + 1)); } catch { console.log("bad JSON args"); break; } }
            const r = await mcp.callTool(name, args);
            console.log(BurpMcp.toolText(r) || JSON.stringify(r));
            store.tool(name, args, BurpMcp.toolText(r), !!r?.isError);
            break;
          }
          case "status": console.log(JSON.stringify({ target: agent.target, scope: agent.scope, model: agent.model, gates: agent.gateRisky, burstMax, ...store.summary() }, null, 2)); break;
          case "memory":
            for (const e of store.recent(12)) {
              const tag = e.type === "tool" ? `tool:${e.tool}` : e.type;
              console.log(`  [${tag}] ${(e.text || e.note || e.content || e.result || "").slice(0, 140)}`);
            }
            break;
          default: console.log("unknown command — /help");
        }
      } else {
        agent.addInstruction(input);
        await runBurst();
      }
    } catch (e) {
      console.log("!! " + (e?.message || e));
    }
    rl.prompt();
  }
  await shutdown(0); // stdin closed (EOF / pipe end)
}

let shuttingDown = false;
async function shutdown(code) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log("\nclosing… session saved to " + store.file);
  await mcp.close().catch(() => {});
  try { rl.close(); } catch {}
  process.exit(code);
}

process.on("SIGINT", () => shutdown(0));
main().catch(async (e) => { console.error("fatal: " + (e?.message || e)); await mcp.close().catch(() => {}); process.exit(1); });
