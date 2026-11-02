import { test } from "node:test";
import assert from "node:assert/strict";
import { pollDelay, linkSince, deviceQuery, watch, SETUP_LINK_TTL } from "../static/watch.js";

test("polling is brisk at first, then backs off to every ten seconds", () => {
  for (let i = 0; i < 15; i++) assert.equal(pollDelay(i), 2000);
  let last = 2000;
  for (let i = 15; i < 60; i++) {
    const d = pollDelay(i);
    assert.ok(d >= last && d <= 10_000, `attempt ${i}: ${d}`);
    last = d;
  }
  assert.equal(pollDelay(100), 10_000);
});

test("since is the link's making by the server's clock, less a minute", () => {
  const expires = "2026-11-02T10:30:00Z";
  assert.equal(linkSince(expires).toISOString(), new Date(Date.parse(expires) - SETUP_LINK_TTL - 60e3).toISOString());
});

test("named devices are watched by name; unnamed, as new devices", () => {
  const since = new Date("2026-11-02T10:00:00Z");
  assert.deepEqual(deviceQuery("kids", "tablet", since), { profile: "kids", since: "2026-11-02T10:00:00.000Z", device: "tablet" });
  assert.deepEqual(deviceQuery("kids", "", since), { profile: "kids", since: "2026-11-02T10:00:00.000Z", new: "true" });
});

// A fake clock: sleeping advances it.
function clock() {
  let now = 0;
  return { now: () => now, sleep: async (ms) => { now += ms; } };
}

test("watch returns the device once it appears, retrying errors", async () => {
  const c = clock();
  let calls = 0;
  const found = await watch({
    query: {}, until: 60_000, ...c,
    fetch: async () => {
      calls++;
      if (calls === 2) throw new Error("server restarting");
      return { devices: calls < 4 ? [] : [{ device: "tablet" }] };
    },
  });
  assert.deepEqual(found, { device: "tablet" });
  assert.equal(calls, 4);
  assert.equal(c.now(), 6000);
});

test("watch gives up when the link expires, or it's stopped", async () => {
  const c = clock();
  assert.equal(await watch({ query: {}, until: 30_000, ...c, fetch: async () => ({ devices: [] }) }), null);
  assert.ok(c.now() > 30_000 && c.now() <= 40_000, `stopped at ${c.now()}: within a poll of expiring`);

  const ctl = new AbortController();
  let calls = 0;
  const result = await watch({ query: {}, until: 1e9, signal: ctl.signal, ...clock(), fetch: async () => { if (++calls === 3) ctl.abort(); return { devices: [] }; } });
  assert.equal(result, null);
  assert.equal(calls, 3);

  const abort = Object.assign(new Error("aborted"), { name: "AbortError" });
  assert.equal(await watch({ query: {}, until: 1e9, ...clock(), fetch: async () => { throw abort; } }), null);
});
