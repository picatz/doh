import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  pushSupported, subscribe, unsubscribe, thisBrowser, subscriptionID, decodeKey, prepare, PushError, SW_URL, POLICY,
} from "../static/push.js";

// A VAPID public key, as GET /alerts/push-key gives it (RFC 8292's example).
const KEY = "BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs";
const ENDPOINT = "https://fcm.googleapis.com/fcm/send/abc";

// fakeWindow is a browser with what push.js uses, recording what's done.
function fakeWindow({ permission = "granted", existing = null, trustedTypes = true } = {}) {
  const log = [];
  let sub = existing;
  const makeSub = (key) => ({
    endpoint: ENDPOINT,
    options: { applicationServerKey: key.buffer },
    toJSON() { return { endpoint: ENDPOINT, expirationTime: null, keys: { p256dh: "p", auth: "a" } }; },
    async unsubscribe() { log.push(["unsubscribe", this.endpoint]); sub = null; return true; },
  });
  const pushManager = {
    async getSubscription() { return sub; },
    async subscribe(opts) {
      log.push(["subscribe", opts.userVisibleOnly, Array.from(opts.applicationServerKey).length]);
      sub = makeSub(opts.applicationServerKey);
      return sub;
    },
  };
  const reg = { pushManager };
  const policies = [];
  const win = {
    isSecureContext: true,
    PushManager: function () {},
    Notification: { async requestPermission() { log.push(["permission"]); return permission; } },
    navigator: {
      serviceWorker: {
        async register(url, opts) { log.push(["register", String(url), opts.scope]); return reg; },
        async getRegistration() { return reg; },
      },
    },
    crypto: globalThis.crypto,
    log,
    policies,
    setSub(s) { sub = s; },
  };
  if (trustedTypes) {
    win.trustedTypes = {
      createPolicy(name, rules) {
        policies.push([name, Object.keys(rules)]);
        return { createScriptURL: (u) => ({ toString: () => rules.createScriptURL(u) }) };
      },
    };
  }
  return { win, makeSub };
}

// fakeAPI answers like doh's API, recording calls.
function fakeAPI() {
  const calls = [];
  const api = async (method, path, opts = {}) => {
    calls.push([method, path, opts.body]);
    if (path === "/alerts/push-key") return { public_key: KEY };
    if (method === "POST") return { destination: { id: "d1", type: "push", state: "active" } };
    return null;
  };
  return { api, calls };
}

test("pushSupported needs a secure context, a service worker, Push, and notifications", () => {
  const { win } = fakeWindow();
  assert.equal(pushSupported(win), true);
  assert.equal(pushSupported({ ...win, isSecureContext: false }), false);
  assert.equal(pushSupported({ ...win, PushManager: undefined }), false);
  assert.equal(pushSupported({ ...win, Notification: undefined }), false);
  assert.equal(pushSupported({ ...win, navigator: {} }), false);
  assert.equal(pushSupported({}), false);
});

test("subscribe asks first, then subscribes with doh's key and adds the destination", async () => {
  const { win } = fakeWindow();
  const { api, calls } = fakeAPI();
  const dest = await subscribe(api, { name: "Alex's phone", win });
  assert.deepEqual(dest, { id: "d1", type: "push", state: "active" });
  const at = (what) => win.log.findIndex((l) => l[0] === what);
  assert.ok(at("permission") >= 0 && at("permission") < at("subscribe"), "permission is asked before subscribing");
  assert.deepEqual(win.log.find((l) => l[0] === "register"), ["register", SW_URL, "/"]);
  assert.deepEqual(win.log.find((l) => l[0] === "subscribe"), ["subscribe", true, 65]);
  assert.deepEqual(calls.at(-1), ["POST", "/alerts/destinations", {
    type: "push", name: "Alex's phone", subscription: { endpoint: ENDPOINT, expirationTime: null, keys: { p256dh: "p", auth: "a" } },
  }]);
});

test("the Trusted Types policy makes only the worker's URL", async () => {
  const { win } = fakeWindow();
  await subscribe(fakeAPI().api, { win });
  await subscribe(fakeAPI().api, { win });
  assert.deepEqual(win.policies, [[POLICY, ["createScriptURL"]]], "one policy, created once, with only createScriptURL");

  // The rules refuse any other URL.
  let rules;
  const spy = { createPolicy(name, r) { rules = r; return { createScriptURL: (u) => r.createScriptURL(u) }; } };
  const { win: w2 } = fakeWindow({ trustedTypes: false });
  w2.trustedTypes = spy;
  await subscribe(fakeAPI().api, { win: w2 });
  assert.equal(rules.createScriptURL(SW_URL), SW_URL);
  for (const bad of ["/sw.js?x", "/ui/sw.js", "https://evil.example/sw.js", "data:text/javascript,1", " /sw.js"]) {
    assert.throws(() => rules.createScriptURL(bad), TypeError, bad);
  }
});

test("without Trusted Types, the worker's URL is a string", async () => {
  const { win } = fakeWindow({ trustedTypes: false });
  await subscribe(fakeAPI().api, { win });
  assert.equal(win.log.find((l) => l[0] === "register")[1], SW_URL);
});

test("subscribe refuses without permission or support, saying why", async () => {
  const { api, calls } = fakeAPI();
  await assert.rejects(subscribe(api, { win: fakeWindow({ permission: "denied" }).win }), (e) => e instanceof PushError && e.code === "denied");
  await assert.rejects(subscribe(api, { win: fakeWindow({ permission: "default" }).win }), (e) => e.code === "denied");
  await assert.rejects(subscribe(api, { win: {} }), (e) => e.code === "unsupported");
  assert.ok(!calls.some((c) => c[0] === "POST"), "nothing was added");
});

test("a subscription with another key is replaced", async () => {
  const { win, makeSub } = fakeWindow();
  win.setSub(makeSub(new Uint8Array(65).fill(9)));
  await subscribe(fakeAPI().api, { win });
  assert.ok(win.log.some((l) => l[0] === "unsubscribe"));
  assert.ok(win.log.some((l) => l[0] === "subscribe"));

  // One with doh's key is kept.
  const again = fakeWindow();
  again.win.setSub(again.makeSub(decodeKey(KEY)));
  await subscribe(fakeAPI().api, { win: again.win });
  assert.ok(!again.win.log.some((l) => l[0] === "subscribe" || l[0] === "unsubscribe"));
});

test("subscriptionID matches the server's: SHA-256 of the endpoint, base64url", async () => {
  const want = createHash("sha256").update(ENDPOINT).digest("base64url");
  assert.equal(await subscriptionID(ENDPOINT), want);
});

test("thisBrowser and unsubscribe find this browser among the destinations", async () => {
  const { win, makeSub } = fakeWindow();
  const id = await subscriptionID(ENDPOINT);
  const dests = [
    { id: "w1", type: "webhook" },
    { id: "p0", type: "push", subscription: "someone-else" },
    { id: "p1", type: "push", subscription: id },
  ];
  assert.equal(await thisBrowser(dests, win), null, "not subscribed");
  assert.equal(await unsubscribe(fakeAPI().api, dests, win), false);

  win.setSub(makeSub(decodeKey(KEY)));
  assert.equal((await thisBrowser(dests, win)).id, "p1");
  const { api, calls } = fakeAPI();
  assert.equal(await unsubscribe(api, dests, win), true);
  assert.deepEqual(calls, [["DELETE", "/alerts/destinations/p1", undefined]]);
  assert.ok(win.log.some((l) => l[0] === "unsubscribe"));
});

test("prepare fetches the key once, and fails quietly", async () => {
  const { win } = fakeWindow();
  const { api, calls } = fakeAPI();
  assert.equal(await prepare(api, win), true);
  await subscribe(api, { win });
  assert.equal(calls.filter((c) => c[1] === "/alerts/push-key").length, 1);
  assert.equal(await prepare(async () => { throw new Error("offline"); }, win), false);
  assert.equal(await prepare(api, {}), false);
});

test("decodeKey reads base64url with or without padding", () => {
  assert.equal(decodeKey(KEY).length, 65);
  assert.equal(decodeKey(KEY)[0], 4);
  assert.deepEqual(Array.from(decodeKey("-_8")), [0xfb, 0xff]);
  assert.deepEqual(Array.from(decodeKey("-_8=")), [0xfb, 0xff]);
});

test("permission is asked at once, while the click still counts", async () => {
  const { win } = fakeWindow();
  const done = subscribe(fakeAPI().api, { win });
  assert.ok(win.log.some((l) => l[0] === "permission"), "asked in the same task as the click");
  await done;
});
