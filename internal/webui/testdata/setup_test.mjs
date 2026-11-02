import { test } from "node:test";
import assert from "node:assert/strict";
import { setupSteps, progress, plainDNSClients, isFirstRun, hasDevice, isLoopback, STEPS } from "../static/setup.js";

const operatorAdmin = { admin: true, operator: true, destinations: [] };
const ids = (steps) => steps.map((s) => s.id);
const done = (steps) => Object.fromEntries(steps.map((s) => [s.id, s.done]));

test("a new server's checklist has every step, none done", () => {
  const steps = setupSteps(operatorAdmin);
  assert.deepEqual(ids(steps), STEPS.map((s) => s.id));
  assert.deepEqual(progress(steps), { done: 0, total: 4, complete: false, next: steps[0] });
});

test("steps apply only to whom they can", () => {
  assert.deepEqual(ids(setupSteps({ admin: false, operator: true })), ["passkey"], "readers can only add a passkey");
  assert.deepEqual(ids(setupSteps({ admin: true, operator: false, destinations: [] })), ["passkey", "device", "alerts"], "a tenant's router isn't the server's concern");
  assert.deepEqual(ids(setupSteps({ admin: true, operator: true, destinations: null })), ["passkey", "device", "network"], "alerts unknown, not offered");
});

test("steps are done from what the server knows", () => {
  const steps = setupSteps({
    ...operatorAdmin,
    person: "p_1",
    profiles: [{ id: "kids", devices: [{ name: "kids-ipad" }] }],
    destinations: [{ id: "d1" }],
    devices: [
      { transport: "udp", client: "192.168.1.20" },
      { transport: "tcp", client: "192.168.1.21" },
    ],
  });
  assert.deepEqual(done(steps), { passkey: true, device: true, alerts: true, network: true });
  assert.equal(progress(steps).complete, true);
  assert.equal(progress(steps).next, null);
});

test("a router is seen by devices asking over plain DNS, not by the server asking itself", () => {
  const devices = [
    { transport: "udp", client: "127.0.0.1" },
    { transport: "udp", client: "::1" },
    { transport: "doh", client: "192.168.1.5" },
    { transport: "udp", client: "192.168.1.20" },
    { transport: "udp", client: "192.168.1.20", device: "x" },
  ];
  assert.deepEqual(plainDNSClients(devices), ["192.168.1.20"]);
  assert.equal(done(setupSteps({ ...operatorAdmin, devices })).network, false, "one device could be set up by hand");
  assert.equal(done(setupSteps({ ...operatorAdmin, devices, prefs: { networkDone: true } })).network, true, "someone said so");
  assert.ok(isLoopback("127.0.0.53") && isLoopback("::1") && !isLoopback("10.0.0.1") && !isLoopback(""));
});

test("a device counts once it's named, by a profile or its DoH path, from elsewhere", () => {
  assert.equal(hasDevice([], [{ device: "phone", client: "192.168.1.9" }]), true);
  assert.equal(hasDevice([], [{ device: "phone", client: "127.0.0.1" }]), false);
  assert.equal(hasDevice([{ devices: [] }], [{ client: "192.168.1.9" }]), false);
});

test("first run is a new server, to an admin", () => {
  assert.equal(isFirstRun({ admin: true }), true);
  assert.equal(isFirstRun({ admin: false }), false);
  assert.equal(isFirstRun({ admin: true, passkeysRequired: true }), false);
  assert.equal(isFirstRun({ admin: true, devices: [{ client: "192.168.1.9", transport: "udp" }] }), false);
  assert.equal(isFirstRun({ admin: true, devices: [{ client: "127.0.0.1", transport: "udp" }] }), true, "the server testing itself");
});
