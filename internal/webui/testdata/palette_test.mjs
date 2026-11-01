import { test } from "node:test";
import assert from "node:assert/strict";
import { score, rank, looksLikeDomain } from "../static/palette.js";

const commands = [
  { id: "overview", title: "Overview", group: "Go to" },
  { id: "activity", title: "Activity", group: "Go to", keywords: ["query log", "logs"] },
  { id: "new-sa", title: "New service account", group: "Actions" },
  { id: "unseen", title: "Unseen alarms", group: "Actions" },
  { id: "theme", title: "Use the dark theme", group: "Preferences", hidden: true },
];

test("score needs every character, in order", () => {
  assert.equal(score("xyz", "Overview"), -1);
  assert.equal(score("wo", "Overview") >= -1, true);
  assert.equal(score("", "anything"), 0);
  assert.ok(score("ov", "Overview") > score("ve", "Overview"), "word starts win");
});

test("rank prefers word starts and keeps the given order without a query", () => {
  assert.deepEqual(rank(commands, "").map((c) => c.id), ["overview", "activity", "new-sa", "unseen"]);
  assert.equal(rank(commands, "nsa")[0].id, "new-sa");
  assert.equal(rank(commands, "query log")[0].id, "activity", "keywords match");
  assert.equal(rank(commands, "dark")[0].id, "theme", "hidden commands appear when searched for");
  assert.deepEqual(rank(commands, "zzz"), []);
});

test("looksLikeDomain", () => {
  for (const d of ["example.com", "ads.example.com", "a.b.c.d.io", "x.co.", "_dmarc.example.com", "EXAMPLE.COM"]) {
    assert.ok(looksLikeDomain(d), d);
  }
  for (const d of ["", "overview", "new service account", "example", "1.2.3.4", "-bad.com", "a..com", "a.b-", "http://x.com"]) {
    assert.ok(!looksLikeDomain(d), d);
  }
});
