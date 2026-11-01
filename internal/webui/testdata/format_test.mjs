import { test } from "node:test";
import assert from "node:assert/strict";
import { fromNow, formatDate } from "../static/format.js";

const en = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
const now = Date.UTC(2026, 10, 1, 12);
const at = (ms) => new Date(now + ms).toISOString();
const minute = 6e4, hour = 36e5, day = 864e5;

test("fromNow picks the unit people would", () => {
  for (const [ms, want] of [
    [30e3, "just now"],
    [-30e3, "just now"],
    [30 * minute, "in 30 minutes"],
    [hour, "in 1 hour"],
    [-2 * hour, "2 hours ago"],
    [day, "tomorrow"],
    [1.5 * day, "in 2 days"],
    [9 * day, "in 9 days"],
    [45 * day, "in 45 days"],
    [90 * day - 1, "in 3 months"],
    [366 * day, "in 12 months"],
    [-3 * 365 * day, "3 years ago"],
  ]) {
    assert.equal(fromNow(at(ms), now, en), want, `${ms}ms`);
  }
});

test("fromNow and formatDate say nothing for nonsense", () => {
  assert.equal(fromNow("not a time", now, en), "");
  assert.equal(formatDate("not a time"), "");
  assert.notEqual(formatDate(at(0)), "");
});
