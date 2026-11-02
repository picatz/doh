// push.js subscribes this browser to doh's alerts, as Web Push
// notifications, through the service worker at /sw.js.
//
// The UI calls it with its own API function, api(method, path, {body}),
// which resolves to the response's JSON:
//
//   import { pushSupported, prepare, subscribe, unsubscribe, thisBrowser } from "./push.js";
//
//   if (pushSupported()) prepare(api);              // when Settings › Alerts opens
//   const dest = await subscribe(api, { name });    // in a click handler
//   const mine = await thisBrowser(alerts.destinations);
//   await unsubscribe(api, alerts.destinations);    // in a click handler
//
// Errors are PushError, with a code: "unsupported", "denied" (the person
// blocked notifications, which only they can undo, in the browser's site
// settings), or "failed".

export const SW_URL = "/sw.js";

// POLICY is the one Trusted Types policy the UI's content security policy
// allows. Registering a service worker takes a TrustedScriptURL; this
// policy makes one for the worker's own URL, and nothing else.
export const POLICY = "doh-sw";

// PushError is why subscribing didn't work.
export class PushError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PushError";
    this.code = code;
  }
}

// pushSupported reports whether this browser can get push notifications
// from this page: it needs a secure context (https, or localhost), a
// service worker, the Push API, and notifications. On iPhone and iPad,
// that's only once the UI is added to the home screen.
export function pushSupported(win = globalThis) {
  return Boolean(win.isSecureContext && win.navigator?.serviceWorker && win.PushManager && win.Notification);
}

const policies = new WeakMap();

// workerURL returns the service worker's URL, as a TrustedScriptURL
// where the browser has Trusted Types.
function workerURL(win) {
  const tt = win.trustedTypes;
  if (!tt?.createPolicy) return SW_URL;
  let policy = policies.get(tt);
  if (!policy) {
    policy = tt.createPolicy(POLICY, {
      createScriptURL(url) {
        if (url !== SW_URL) throw new TypeError(`${POLICY} only allows ${SW_URL}`);
        return url;
      },
    });
    policies.set(tt, policy);
  }
  return policy.createScriptURL(SW_URL);
}

// register registers the service worker, or returns it if it's there.
export function register(win = globalThis) {
  return win.navigator.serviceWorker.register(workerURL(win), { scope: "/", updateViaCache: "none" });
}

// decodeKey decodes base64url, as doh gives its push key, to bytes.
export function decodeKey(s) {
  const b64 = String(s).replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

// sameBytes reports whether two keys, as ArrayBuffers or views, are equal.
function sameBytes(a, b) {
  if (!a || !b) return false;
  const x = new Uint8Array(a.buffer ?? a, a.byteOffset ?? 0, a.byteLength);
  const y = new Uint8Array(b.buffer ?? b, b.byteOffset ?? 0, b.byteLength);
  return x.length === y.length && x.every((v, i) => v === y[i]);
}

// subscriptionID returns how doh names a browser's subscription in its
// destinations, without knowing the subscription: the SHA-256 of its
// endpoint, as unpadded base64url.
export async function subscriptionID(endpoint, subtle = globalThis.crypto.subtle) {
  const sum = new Uint8Array(await subtle.digest("SHA-256", new TextEncoder().encode(endpoint)));
  return btoa(String.fromCharCode(...sum)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const keys = new WeakMap();

// pushKey returns doh's VAPID public key, fetched once per API function.
function pushKey(api) {
  let key = keys.get(api);
  if (!key) {
    key = api("GET", "/alerts/push-key").then((r) => decodeKey(r.public_key));
    key.catch(() => keys.delete(api));
    keys.set(api, key);
  }
  return key;
}

// prepare registers the service worker and fetches doh's push key ahead
// of a click, so subscribe has nothing to wait for after asking the
// person: Safari only lets a page subscribe soon after a tap.
export function prepare(api, win = globalThis) {
  if (!pushSupported(win)) return Promise.resolve(false);
  return Promise.all([register(win), pushKey(api)]).then(() => true, () => false);
}

// current returns this browser's subscription, if it has one.
export async function current(win = globalThis) {
  if (!pushSupported(win)) return null;
  const reg = await win.navigator.serviceWorker.getRegistration("/");
  return (await reg?.pushManager.getSubscription()) ?? null;
}

// thisBrowser returns the push destination, of destinations as GET
// /alerts lists them, that is this browser, or null.
export async function thisBrowser(destinations, win = globalThis) {
  const sub = await current(win);
  if (!sub) return null;
  const id = await subscriptionID(sub.endpoint, win.crypto.subtle);
  return (destinations ?? []).find((d) => d.type === "push" && d.subscription === id) ?? null;
}

// subscribe asks the person to allow notifications, subscribes this
// browser with doh's key, and adds it as a push destination named name,
// returning the destination. Call it from a click: browsers only ask for
// permission then. Subscribing again renews the same destination.
export async function subscribe(api, { name = "", win = globalThis } = {}) {
  if (!pushSupported(win)) {
    throw new PushError("unsupported", "This browser can't get notifications from this page. On iPhone and iPad, add doh to the Home Screen first.");
  }
  // Start what doesn't need permission while the browser asks for it.
  const ready = Promise.all([register(win), pushKey(api)]);
  ready.catch(() => {});
  const permission = await win.Notification.requestPermission();
  if (permission !== "granted") {
    throw new PushError("denied", "Notifications are blocked for this site. Allow them in the browser's site settings, then try again.");
  }

  let reg, key;
  try {
    [reg, key] = await ready;
  } catch (err) {
    throw new PushError("failed", `Couldn't set up notifications: ${err.message}`);
  }
  let sub = await reg.pushManager.getSubscription();
  if (sub && !sameBytes(sub.options?.applicationServerKey, key)) {
    // Subscribed with a key doh no longer has, such as before a reinstall.
    await sub.unsubscribe();
    sub = null;
  }
  try {
    sub ??= await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
  } catch (err) {
    throw new PushError("failed", `The browser couldn't subscribe: ${err.message}`);
  }
  const res = await api("POST", "/alerts/destinations", { body: { type: "push", name, subscription: sub.toJSON() } });
  return res.destination;
}

// unsubscribe removes this browser from doh's push destinations, of
// destinations as GET /alerts lists them, and ends its subscription. It
// reports whether there was one.
export async function unsubscribe(api, destinations, win = globalThis) {
  const sub = await current(win);
  if (!sub) return false;
  const mine = await thisBrowser(destinations, win);
  if (mine) await api("DELETE", `/alerts/destinations/${encodeURIComponent(mine.id)}`);
  await sub.unsubscribe();
  return true;
}
