import { test } from "node:test";
import assert from "node:assert/strict";
import { PRESETS, matchPreset, presetPatch, undoPatch } from "../static/presets.js";

const byID = Object.fromEntries(PRESETS.map((p) => [p.id, p]));

test("a fresh profile, with doh's defaults, matches Essential", () => {
  assert.equal(matchPreset({ security: { rebinding: true, homograph: true }, lists: ["threat-intel"] }), "essential");
});

test("each preset, applied, is matched again", () => {
  for (const preset of PRESETS) {
    const p = { security: {}, lists: [] };
    const patch = presetPatch(p, preset);
    assert.equal(matchPreset({ ...p, ...patch }), preset.id, preset.id);
  }
});

test("presets keep custom and unmanaged lists", () => {
  const p = { security: {}, lists: ["https://example.com/mine.txt", "social", "hagezi-light"] };
  const patch = presetPatch(p, byID.kids);
  assert.ok(patch.lists.includes("https://example.com/mine.txt"));
  assert.ok(patch.lists.includes("social"));
  assert.ok(!patch.lists.includes("hagezi-light"), "a managed list the preset doesn't use goes");
  assert.equal(new Set(patch.lists).size, patch.lists.length, "no duplicates");
  // Unmanaged lists don't change which preset matches.
  assert.equal(matchPreset({ ...p, ...patch }), "kids");
});

test("anything else is its own mix", () => {
  assert.equal(matchPreset({ security: { rebinding: true }, lists: ["threat-intel"] }), "");
  assert.equal(matchPreset({ ...presetPatch({}, byID.strict), safe_search: true }), "");
});

test("undo puts back what a preset changed", () => {
  const before = { security: { rebinding: true, tunneling: true }, lists: ["threat-intel", "social"], safe_search: true };
  const undo = undoPatch(before);
  const after = { ...before, ...presetPatch(before, byID.essential) };
  const restored = { ...after, ...undo, security: { ...after.security, ...undo.security } };
  assert.deepEqual(restored.lists, before.lists);
  assert.equal(restored.safe_search, true);
  assert.equal(restored.security.tunneling, true);
  assert.equal(restored.security.homograph, false);
});
