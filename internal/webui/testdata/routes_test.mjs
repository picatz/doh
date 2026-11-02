import { test } from "node:test";
import assert from "node:assert/strict";
import { parseRoute, routeHash, settingsFor, SETTINGS, PROFILE_SECTIONS, VIEWS } from "../static/routes.js";

const plain = (r) => ({ view: r.view, arg: r.arg, query: Object.fromEntries(r.query), moved: r.moved });

test("parseRoute reads views, arguments, and queries", () => {
  assert.deepEqual(plain(parseRoute("#/profiles/kids?tab=apps")), { view: "profiles", arg: "kids", query: { tab: "apps" }, moved: false });
  assert.deepEqual(plain(parseRoute("#/settings/alerts")), { view: "settings", arg: "alerts", query: {}, moved: false });
  assert.deepEqual(plain(parseRoute("#/logs?status=blocked&q=ads")), { view: "logs", arg: "", query: { status: "blocked", q: "ads" }, moved: false });
  assert.deepEqual(plain(parseRoute("#/setup")), { view: "setup", arg: "", query: {}, moved: false });
});

test("unknown places are the Overview, and unknown settings the hub", () => {
  for (const hash of ["", "#", "#/nowhere", "#signin=abc", "#/OVERVIEW", "javascript:alert(1)"]) {
    assert.equal(parseRoute(hash).view, "overview", hash);
  }
  assert.deepEqual(plain(parseRoute("#/settings/nope")), { view: "settings", arg: "", query: {}, moved: false });
  // A malformed escape is ignored rather than thrown.
  assert.equal(parseRoute("#/profiles/%E0%A4%A").arg, "");
});

test("old places land where they went", () => {
  assert.deepEqual(plain(parseRoute("#/security")), { view: "settings", arg: "account", query: {}, moved: true });
  assert.deepEqual(plain(parseRoute("#/tenants")), { view: "settings", arg: "tenants", query: {}, moved: true });
});

test("routeHash round-trips, leaving out empty values", () => {
  assert.equal(routeHash("profiles", "kids", { tab: "connect", x: "", y: null }), "#/profiles/kids?tab=connect");
  assert.equal(routeHash("logs", "", { q: "a b&c" }), "#/logs?q=a+b%26c");
  for (const [view, arg, query] of [["profiles", "kids tablets/2", { tab: "apps" }], ["settings", "api", {}], ["overview", "", {}]]) {
    const r = parseRoute(routeHash(view, arg, query));
    assert.deepEqual([r.view, r.arg, Object.fromEntries(r.query)], [view, arg, query]);
  }
});

test("settings sections follow who's looking", () => {
  const ids = (who) => settingsFor(who).map((s) => s.id);
  assert.deepEqual(ids({ operator: true, admin: true }), SETTINGS.map((s) => s.id));
  assert.ok(!ids({ operator: false, admin: true }).includes("tenants"), "tenants see no Tenants section");
  assert.ok(!ids({ operator: true, admin: false }).includes("alerts"), "readers see no Alerts section");
  assert.ok(!ids({ operator: true, admin: false }).includes("audit"), "readers see no change history");
  assert.ok(ids({ operator: false, admin: true }).includes("audit"), "a tenant's admins see their own change history");
  assert.ok(ids({ operator: false, admin: false }).includes("account"), "everyone has an account");
});

test("every section and view has a name and an icon", () => {
  for (const s of [...SETTINGS, ...PROFILE_SECTIONS]) assert.ok(s.id && s.title && s.icon, JSON.stringify(s));
  assert.equal(new Set(VIEWS).size, VIEWS.length);
});
