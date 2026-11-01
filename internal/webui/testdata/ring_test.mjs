import { test } from "node:test";
import assert from "node:assert/strict";
import { angle, point, sector, thickness, sprinkleCount, sprinkles, totalOf, SIZE } from "../static/ring.js";

const close = (a, b, msg) => assert.ok(Math.abs(a - b) < 1e-6, `${msg}: ${a} ≉ ${b}`);

test("the ring is a 24-hour clock, midnight at the top", () => {
  assert.equal(angle(0), 0);
  assert.equal(angle(6), 90);
  assert.equal(angle(12), 180);
  assert.equal(angle(24), 0);
  assert.equal(angle(-1), 345);
  const [x, y] = point(100, 0);
  close(x, SIZE / 2, "top x");
  close(y, SIZE / 2 - 100, "top y");
  const [x6] = point(100, angle(6));
  close(x6, SIZE / 2 + 100, "6 AM is at the right");
});

test("sectors are closed annular paths", () => {
  const d = sector(66, 100, 0, 15);
  assert.match(d, /^M[\d.]+ [\d.]+A100 100 0 0 1 [\d.]+ [\d.]+L[\d.]+ [\d.]+A66 66 0 0 0 [\d.]+ [\d.]+Z$/);
  assert.match(sector(66, 100, 0, 200), /A100 100 0 1 1/, "large arcs past 180°");
});

test("thickness shows quiet hours, and grows with traffic", () => {
  assert.equal(thickness(0, 100), 0);
  assert.equal(thickness(5, 0), 0);
  assert.ok(thickness(1, 1000) >= 7, "any traffic shows");
  assert.equal(thickness(1000, 1000), 34);
  assert.ok(thickness(250, 1000) < thickness(500, 1000));
});

test("sprinkles grow with each tenfold, up to four, and stay put", () => {
  assert.deepEqual([0, 1, 9, 10, 99, 100, 1e6].map(sprinkleCount), [0, 1, 1, 2, 2, 3, 4]);
  assert.deepEqual(sprinkles(7, 30, 20), sprinkles(7, 30, 20), "stable across renders");
  for (const s of sprinkles(7, 1e4, 20)) {
    assert.ok(s.a > 105 && s.a < 120, `within 7 AM's sector: ${s.a}`);
    assert.ok(s.r >= 66 && s.r <= 66 + 20, `on the glaze: ${s.r}`);
  }
});

test("totalOf counts every status", () => {
  assert.equal(totalOf({ allowed: 3, blocked: 2, rewritten: 1, errors: 4 }), 10);
  assert.equal(totalOf({}), 0);
});
