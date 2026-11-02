import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const source = readFileSync(fileURLToPath(new URL("../static/sw.js", import.meta.url)), "utf8");
const ORIGIN = "https://admin.dns.example.com";

// worker runs sw.js in a fake service worker global, returning its event
// listeners and what it did.
function worker({ windows = [] } = {}) {
  const listeners = {};
  const did = { shown: [], opened: [], focused: [], navigated: [] };
  const self = {
    location: new URL(ORIGIN + "/sw.js"),
    addEventListener(type, fn) { listeners[type] = fn; },
    skipWaiting() {},
    registration: { async showNotification(title, options) { did.shown.push({ title, options }); } },
    clients: {
      claim: async () => {},
      async matchAll(opts) { did.matchAll = opts; return windows; },
      async openWindow(url) { did.opened.push(url); return { url }; },
    },
  };
  for (const w of windows) {
    w.focus = async () => { did.focused.push(w.url); return w; };
    w.navigate ??= async (url) => { did.navigated.push(url); w.url = url; return w; };
  }
  vm.runInNewContext(source, { self, URL, Date, Number, String, console });
  return { listeners, did };
}

// fire dispatches an event, waiting for what it waits for.
async function fire(listener, event) {
  let wait = Promise.resolve();
  listener({ ...event, waitUntil(p) { wait = p; } });
  await wait;
}

const pushed = (message) => ({ data: { json: () => (typeof message === "string" ? JSON.parse(message) : message) } });

test("the worker caches nothing: no fetch handler", () => {
  const { listeners } = worker();
  assert.deepEqual(Object.keys(listeners).sort(), ["activate", "install", "notificationclick", "push"]);
  assert.doesNotMatch(source, /caches\.|addEventListener\("fetch"|importScripts/);
});

test("a pushed alert shows as a notification", async () => {
  const { listeners, did } = worker();
  await fire(listeners.push, pushed({
    id: "msg_1", kind: "threat", title: "Threat blocked on kids-ipad", body: "doh blocked evil.example.",
    tag: "doh:threat:kids/kids-ipad", url: ORIGIN + "/#/logs?q=evil.example", time: "2026-11-02T19:04:05Z",
  }));
  assert.equal(did.shown.length, 1);
  const { title, options } = did.shown[0];
  assert.equal(title, "Threat blocked on kids-ipad");
  assert.equal(options.body, "doh blocked evil.example.");
  assert.equal(options.tag, "doh:threat:kids/kids-ipad");
  assert.equal(options.renotify, true);
  assert.equal(options.icon, "/ui/icon-192.png");
  assert.equal(options.badge, "/ui/badge-96.png");
  assert.equal(options.timestamp, Date.parse("2026-11-02T19:04:05Z"));
  assert.equal(options.data.url, ORIGIN + "/#/logs?q=evil.example");
});

test("anything else pushed still shows, safely", async () => {
  for (const data of [null, { json() { throw new SyntaxError("not JSON"); } }, { json: () => 42 }, { json: () => ({ title: 7, body: ["x"] }) }]) {
    const { listeners, did } = worker();
    await fire(listeners.push, { data });
    assert.equal(did.shown.length, 1, "a push must always show something");
    assert.equal(did.shown[0].title, "doh");
    assert.match(did.shown[0].options.body, /needs you/);
    assert.equal(did.shown[0].options.tag, undefined);
    assert.equal(did.shown[0].options.data.url, ORIGIN + "/");
  }

  const { listeners, did } = worker();
  await fire(listeners.push, pushed({ title: "t".repeat(5000), body: "b".repeat(5000), tag: "x".repeat(5000) }));
  assert.equal(did.shown[0].title.length, 200);
  assert.equal(did.shown[0].options.body.length, 1000);
  assert.equal(did.shown[0].options.tag.length, 200);
});

test("a notification links only to the UI itself", async () => {
  for (const [url, want] of [
    [ORIGIN + "/#/logs", ORIGIN + "/#/logs"],
    ["/#/security", ORIGIN + "/#/security"],
    ["https://evil.example/phish", ORIGIN + "/"],
    ["//evil.example/x", ORIGIN + "/"],
    ["javascript:alert(1)", ORIGIN + "/"],
    ["http://admin.dns.example.com/#/logs", ORIGIN + "/"],
    ["https://admin.dns.example.com:8443/", ORIGIN + "/"],
    [undefined, ORIGIN + "/"],
  ]) {
    const { listeners, did } = worker();
    await fire(listeners.push, pushed({ title: "x", url }));
    assert.equal(did.shown[0].options.data.url, want, String(url));
  }
});

test("tapping a notification focuses the UI and shows the alert", async () => {
  const ui = { url: ORIGIN + "/#/overview" };
  const other = { url: "https://elsewhere.example/" };
  const { listeners, did } = worker({ windows: [other, ui] });
  let closed = false;
  await fire(listeners.notificationclick, { notification: { data: { url: ORIGIN + "/#/logs" }, close() { closed = true; } } });
  assert.ok(closed);
  assert.deepEqual({ ...did.matchAll }, { type: "window", includeUncontrolled: true });
  assert.deepEqual(did.focused, [ORIGIN + "/#/overview"], "focused first, while the tap counts");
  assert.deepEqual(did.navigated, [ORIGIN + "/#/logs"]);
  assert.deepEqual(did.opened, []);
});

test("with no UI open, tapping opens one, on the UI's origin only", async () => {
  const { listeners, did } = worker({ windows: [{ url: "https://elsewhere.example/" }] });
  await fire(listeners.notificationclick, { notification: { data: { url: "https://evil.example/" }, close() {} } });
  assert.deepEqual(did.opened, [ORIGIN + "/"]);
  assert.deepEqual(did.focused, []);
});

test("an uncontrolled window is focused where it is", async () => {
  const ui = { url: ORIGIN + "/", navigate: async () => { throw new TypeError("not controlled"); } };
  const { listeners, did } = worker({ windows: [ui] });
  await fire(listeners.notificationclick, { notification: { data: { url: ORIGIN + "/#/logs" }, close() {} } });
  assert.deepEqual(did.focused, [ORIGIN + "/"]);
  assert.deepEqual(did.opened, []);
});
