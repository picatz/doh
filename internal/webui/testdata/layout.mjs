// layout.mjs checks the UI's layout in a real browser, at phone, tablet,
// and desktop widths, in both themes, for every view: nothing scrolls
// sideways, nothing sticks out of the screen except inside something that
// scrolls, controls are big enough to tap, and nothing logs an error.
//
// It needs only Node and Chrome, driven over the DevTools protocol with
// Node's own WebSocket, so it runs wherever both are installed:
//
//	node layout.mjs CHROME SIGN_IN_URL
//
// It prints a JSON array of problems; empty is good. internal/serve's
// TestLayout runs it against a real server.

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const [chrome, signInURL] = process.argv.slice(2);
if (!chrome || !signInURL) {
  console.error("usage: node layout.mjs CHROME SIGN_IN_URL");
  process.exit(2);
}

// Where to look: every view, and every tab of a profile.
const ROUTES = [
  "#/overview", "#/profiles", "#/profiles/kids",
  "#/profiles/kids?tab=protection", "#/profiles/kids?tab=apps", "#/profiles/kids?tab=lists",
  "#/profiles/kids?tab=devices", "#/profiles/kids?tab=settings",
  "#/logs", "#/explain", "#/security", "#/tenants",
];

// How: the smallest phone people still use, a common one in dark mode, a
// tablet, a laptop, and a wide screen.
const SCREENS = [
  { width: 320, height: 640, scheme: "light" },
  { width: 390, height: 844, scheme: "dark" },
  { width: 768, height: 1024, scheme: "light" },
  { width: 1024, height: 768, scheme: "dark" },
  { width: 1440, height: 900, scheme: "light" },
];

// MIN_TARGET is the smallest a control may be to tap, in CSS pixels
// (WCAG 2.2, 2.5.8 Target Size (Minimum)).
const MIN_TARGET = 24;

// check runs in the page: it returns what's wrong with the layout.
function check(minTarget) {
  const problems = [];
  const name = (el) => {
    const id = el.closest("[id]")?.id;
    const cls = typeof el.className === "string" && el.className ? "." + el.className.trim().split(/\s+/).join(".") : "";
    const text = (el.getAttribute("aria-label") || el.textContent || "").trim().slice(0, 30);
    return `${id ? "#" + id + " " : ""}${el.tagName.toLowerCase()}${cls}${text ? ` "${text}"` : ""}`;
  };
  if (document.documentElement.scrollWidth > innerWidth) {
    problems.push(`the page scrolls sideways: ${document.documentElement.scrollWidth}px wide`);
  }
  const visible = (el) => !el.closest("[hidden], dialog:not([open])") && el.getClientRects().length > 0;
  // Inside something that scrolls or clips, sticking out is by design;
  // that something must fit, and is checked itself.
  const clipped = (el) => {
    for (let a = el.parentElement; a && a !== document.body; a = a.parentElement) {
      if (getComputedStyle(a).overflowX !== "visible") return true;
    }
    return false;
  };
  for (const el of document.querySelectorAll("body *")) {
    if (!visible(el) || clipped(el)) continue;
    const r = el.getBoundingClientRect();
    // Parked wholly off the screen, as a skip link is until it's focused,
    // is by design.
    if (r.width === 0 || r.right <= 0 || r.left >= innerWidth) continue;
    if (el.closest(".visually-hidden")) continue;
    if (r.right > innerWidth + 0.5 || r.left < -0.5) {
      const p = el.parentElement.getBoundingClientRect();
      // Report where it starts sticking out, not every descendant.
      if (p.right <= innerWidth + 0.5 && p.left >= -0.5) problems.push(`${name(el)} sticks out: ${Math.round(r.left)} to ${Math.round(r.right)} of ${innerWidth}px`);
    }
  }
  for (const el of document.querySelectorAll("button, select, summary, input:not([type=hidden]), [role=switch], [role=tab]")) {
    if (!visible(el) || el.closest(".visually-hidden") || el.classList.contains("visually-hidden")) continue;
    const r = el.getBoundingClientRect();
    // Radios and checkboxes inside a label take the label's size.
    const target = el.matches("input[type=radio], input[type=checkbox]:not([role=switch])") && el.closest("label") ? el.closest("label").getBoundingClientRect() : r;
    if (target.width < minTarget - 0.5 || target.height < minTarget - 0.5) {
      problems.push(`${name(el)} is ${Math.round(target.width)}×${Math.round(target.height)}px, under ${minTarget}px to tap`);
    }
  }
  return problems;
}

const dir = mkdtempSync(join(tmpdir(), "doh-layout-"));
const proc = spawn(chrome, [
  "--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
  "--remote-debugging-port=0", `--user-data-dir=${dir}`, "about:blank",
], { stdio: "ignore" });

let ws;
try {
  // Chrome writes its port and path once it listens.
  let port, path;
  for (let i = 0; i < 200 && !port; i++) {
    try {
      [port, path] = readFileSync(join(dir, "DevToolsActivePort"), "utf8").trim().split("\n");
    } catch {
      await sleep(50);
    }
  }
  if (!port) throw new Error("Chrome didn't start");

  ws = new WebSocket(`ws://127.0.0.1:${port}${path}`);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = () => reject(new Error("can't reach Chrome")); });

  let nextID = 0;
  const pending = new Map();
  const errors = [];
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.id !== undefined) {
      const p = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) p.reject(new Error(`${p.method}: ${msg.error.message}`));
      else p.resolve(msg.result);
    } else if (msg.method === "Runtime.exceptionThrown") {
      errors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
    } else if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "error") {
      errors.push(msg.params.args.map((a) => a.value ?? a.description).join(" "));
    } else if (msg.method === "Log.entryAdded" && msg.params.entry.level === "error") {
      errors.push(msg.params.entry.text);
    }
  };
  const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++nextID;
    pending.set(id, { resolve, reject, method });
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });

  const { targetId } = await send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
  const page = (method, params) => send(method, params, sessionId);
  const evaluate = async (expression) => {
    const { result, exceptionDetails } = await page("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (exceptionDetails) throw new Error(exceptionDetails.exception?.description || exceptionDetails.text);
    return result.value;
  };
  const until = async (expression, what) => {
    for (let i = 0; i < 100; i++) {
      if (await evaluate(expression)) return;
      await sleep(50);
    }
    throw new Error(`timed out waiting for ${what}`);
  };
  await Promise.all([page("Runtime.enable"), page("Log.enable"), page("Page.enable")]);

  // Sign in once; the session cookie carries on.
  await page("Page.navigate", { url: signInURL });
  await until(`!document.getElementById("app")?.hidden`, "sign-in");

  const problems = [];
  for (const s of SCREENS) {
    await page("Emulation.setDeviceMetricsOverride", { width: s.width, height: s.height, deviceScaleFactor: 1, mobile: s.width < 720 });
    await page("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: s.scheme }, { name: "prefers-reduced-motion", value: "reduce" }] });
    for (const route of ROUTES) {
      await evaluate(`location.hash = ${JSON.stringify(route)}`);
      // Let it render, then open what's folded away, so that's checked too.
      await sleep(400);
      await evaluate(`document.querySelectorAll("main details").forEach((d) => { d.open = true; })`);
      await sleep(80);
      for (const p of await evaluate(`(${check})(${MIN_TARGET})`)) problems.push(`${s.width}px ${s.scheme} ${route}: ${p}`);
      for (const e of errors.splice(0)) problems.push(`${s.width}px ${s.scheme} ${route}: error: ${e}`);
    }
  }
  console.log(JSON.stringify([...new Set(problems)], null, 1));
} finally {
  ws?.close();
  proc.kill();
  await sleep(100);
  // Chrome may still be writing its profile as it exits.
  rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
