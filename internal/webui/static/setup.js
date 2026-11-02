// The setup checklist: what's left to make a network safe, worked out
// from what the server already knows, so nothing new is stored but
// someone's choice to dismiss it, or to say they've set up their router.
// Pure, so it's tested on its own.

// STEPS say what each step is for, in order.
export const STEPS = [
  {
    id: "passkey", title: "Add a passkey",
    line: "Sign in with Face ID, Touch ID, Windows Hello, or a security key, and make sign-in links need one too.",
  },
  {
    id: "device", title: "Connect your first device",
    line: "Send a phone, tablet, or computer a setup link, and watch it connect.",
  },
  {
    id: "alerts", title: "Turn on alerts",
    line: "Hear about threats and new devices on your phone, as they happen.",
  },
  {
    id: "network", title: "Protect the whole network",
    line: "Point your router at doh, so every device on your Wi-Fi is covered, even ones you can't set up.",
  },
];

// isLoopback reports whether addr is this machine: the server asking
// itself, as a test from its own terminal does, not a device.
export const isLoopback = (addr) => /^127\./.test(addr || "") || addr === "::1";

// plainDNSClients returns the addresses of devices that asked over plain
// DNS, other than the server itself: what a router handing out doh's
// address looks like from here.
export function plainDNSClients(devices = []) {
  const seen = new Set();
  for (const d of devices) {
    if ((d.transport === "udp" || d.transport === "tcp") && d.client && !isLoopback(d.client)) seen.add(d.client);
  }
  return [...seen];
}

// ROUTER_SEEN is how many devices asking over plain DNS make it likely a
// router is sending them: one could be a device set up by hand.
export const ROUTER_SEEN = 2;

// hasDevice reports whether any device is connected or named: a profile
// lists one, or a device the server answered had a name from its DoH path.
export const hasDevice = (profiles = [], devices = []) =>
  profiles.some((p) => (p.devices || []).length) || devices.some((d) => d.device && !isLoopback(d.client));

// setupSteps returns the steps that apply to someone, each with done.
//
//	person       the signed-in person, if they've added a passkey
//	admin        whether they may change things
//	operator     whether they run the server, rather than a tenant
//	profiles     the profiles they see
//	devices      the devices the server has answered, from /devices
//	destinations the alert destinations, or null if unknown
//	prefs        what they've said on this device: { networkDone }
export function setupSteps({ person = "", admin = false, operator = false, profiles = [], devices = [], destinations = null, prefs = {} }) {
  const done = {
    passkey: !!person,
    device: hasDevice(profiles, devices),
    alerts: (destinations || []).length > 0,
    network: plainDNSClients(devices).length >= ROUTER_SEEN || !!prefs.networkDone,
  };
  const applies = {
    passkey: true,
    device: admin,
    alerts: admin && destinations !== null,
    // A tenant's household reaches a shared server over DoH; its router
    // isn't this server's concern.
    network: admin && operator,
  };
  return STEPS.filter((s) => applies[s.id]).map((s) => ({ ...s, done: done[s.id] }));
}

// progress summarizes steps: how many are done, of how many, and the
// first that isn't, if any.
export function progress(steps) {
  const done = steps.filter((s) => s.done).length;
  return { done, total: steps.length, complete: done === steps.length, next: steps.find((s) => !s.done) || null };
}

// isFirstRun reports whether the server looks brand new to an admin: no
// one has a passkey, no device is connected, and nothing has asked it
// anything. Then the UI opens on setup rather than an empty Overview.
export const isFirstRun = ({ admin = false, passkeysRequired = false, profiles = [], devices = [] }) =>
  admin && !passkeysRequired && !hasDevice(profiles, devices) && !devices.some((d) => !isLoopback(d.client));
