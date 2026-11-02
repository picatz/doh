import { test } from "node:test";
import assert from "node:assert/strict";
import { LEVELS, groupPlatforms, guessPlatform, level, signingState } from "../static/platforms.js";

const setup = {
  groups: [{ id: "phones", name: "Phones & tablets" }, { id: "consoles", name: "Game consoles" }, { id: "network", name: "Whole network" }],
  platforms: [
    { id: "apple", group: "phones", name: "iPhone and iPad", protection: { level: "encrypted" } },
    { id: "android", group: "phones", name: "Android", protection: { level: "encrypted" } },
    { id: "consoles", group: "consoles", name: "Xbox, PlayStation, and Switch", protection: { level: "plain" } },
    { id: "router", group: "network", name: "Router", protection: { level: "unavailable" } },
  ],
};
const ids = (groups) => groups.map((g) => [g.group.id, g.platforms.map((p) => p.id)]);

test("platforms come grouped, in the server's order", () => {
  assert.deepEqual(ids(groupPlatforms(setup)), [["phones", ["apple", "android"]], ["consoles", ["consoles"]], ["network", ["router"]]]);
});

test("search finds devices by what people call them, every word", () => {
  assert.deepEqual(ids(groupPlatforms(setup, "ps5")), [["consoles", ["consoles"]]]);
  assert.deepEqual(ids(groupPlatforms(setup, "IPAD")), [["phones", ["apple"]]]);
  assert.deepEqual(ids(groupPlatforms(setup, "phones")), [["phones", ["apple", "android"]]], "a group's name finds its platforms");
  assert.deepEqual(ids(groupPlatforms(setup, "samsung phone")), [["phones", ["android"]]]);
  assert.deepEqual(groupPlatforms(setup, "toaster"), []);
});

test("without groups, and with nothing to set up, it still works", () => {
  assert.deepEqual(ids(groupPlatforms({ platforms: [{ id: "none", name: "Nothing yet" }, { id: "linux", name: "Linux" }] })), [["", ["linux"]]]);
});

test("every level is said in words and a symbol", () => {
  for (const l of Object.values(LEVELS)) assert.ok(l.label && l.icon && l.tone);
  assert.equal(level(setup.platforms[2]).label, "Plain DNS");
  assert.equal(level({}), null);
});

test("the browser's own platform is suggested", () => {
  const all = ["apple", "mac", "android", "windows", "linux", "chromeos"];
  assert.equal(guessPlatform("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)", all), "apple");
  assert.equal(guessPlatform("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", all), "mac");
  assert.equal(guessPlatform("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", all, 5), "apple", "an iPad asks for the desktop site");
  assert.equal(guessPlatform("Mozilla/5.0 (X11; CrOS x86_64 14541.0.0)", all), "chromeos");
  assert.equal(guessPlatform("Mozilla/5.0 (Linux; Android 15; Pixel 9)", all), "android");
  assert.equal(guessPlatform("Mozilla/5.0 (Macintosh)", ["apple"]), "apple");
  assert.equal(guessPlatform("curl/8", all), "");
});

test("Apple profiles are Verified only when signed and trusted", () => {
  assert.equal(signingState(null), null);
  assert.equal(signingState({ signed: true, trusted: true, signer: "dns.example.com" }).verified, true);
  assert.equal(signingState({ signed: true, trusted: false, note: "Its certificate is self-signed." }).verified, false);
  assert.equal(signingState({ signed: true, trusted: false, note: "Its certificate is self-signed." }).line, "Its certificate is self-signed.");
  assert.equal(signingState({ signed: false, trusted: false }).label, "Unverified");
});
