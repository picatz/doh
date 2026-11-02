import { test } from "node:test";
import assert from "node:assert/strict";
import { ACTIONS, actorName, actorsOf, dayLabel, describe, plainSummary } from "../static/audit.js";

test("a profile change reads as a sentence, without IDs", () => {
  const e = {
    actor: { kind: "person", id: "p1", name: "Alex" }, action: "profile.updated",
    summary: "Unblocked TikTok (tiktok) in profile Kids (kids)",
  };
  assert.equal(describe(e), "Alex unblocked TikTok in Kids");
});

test("IDs that aren't made from the name before them stay", () => {
  assert.equal(plainSummary("Blocked Disney+ (disneyplus) in profile Kids (kids-2)"), "Blocked Disney+ (disneyplus) in Kids (kids-2)");
  assert.equal(plainSummary("Created profile Living Room TV (living-room-tv)"), "Created profile Living Room TV");
  assert.equal(plainSummary(""), "");
});

test("every kind of actor has a name", () => {
  assert.equal(actorName({ kind: "token", id: "admin", name: "admin token" }), "The admin token");
  assert.equal(actorName({ kind: "link", name: "sign-in link" }), "Someone (signed in with a link)");
  assert.equal(actorName({ kind: "service_account", id: "sa1", name: "Home Assistant" }), "Home Assistant (a service account)");
  assert.equal(actorName({ kind: "recipient" }), "The email's recipient");
  assert.equal(actorName(undefined), "Someone");
  assert.equal(describe({ actor: { kind: "token", name: "admin token" }, action: "policy.updated" }), "The admin token: policy.updated");
});

test("days are today, yesterday, or a date", () => {
  const now = new Date(2026, 10, 2, 9, 30);
  assert.equal(dayLabel(new Date(2026, 10, 2, 0, 5), now), "Today");
  assert.equal(dayLabel(new Date(2026, 10, 1, 23, 59), now), "Yesterday");
  assert.notEqual(dayLabel(new Date(2026, 9, 20), now), "Yesterday");
});

test("actors are listed once each, keeping those known", () => {
  const events = [
    { actor: { kind: "person", id: "p1", name: "Alex" } },
    { actor: { kind: "person", id: "p1", name: "Alex" } },
    { actor: { kind: "token", id: "admin", name: "admin token" } },
  ];
  const known = actorsOf(events);
  assert.deepEqual(known.map((a) => a.key), ["p1", "admin"]);
  assert.deepEqual(actorsOf([{ actor: { kind: "person", id: "p2", name: "Sam" } }], known).map((a) => a.key), ["p1", "admin", "p2"]);
});

test("the action filters are distinct prefixes", () => {
  const ids = ACTIONS.map(([id]) => id);
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(ids.every((id) => !id.includes(".")));
});
