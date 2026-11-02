// doh's service worker: it shows the alerts doh pushes to this browser,
// and opens the alert's view when one is tapped.
//
// It caches nothing, on purpose. The UI is served with no-cache and is no
// use without the API, and API responses hold query logs, device names,
// and settings that shouldn't sit in a cache on disk for whoever uses the
// device next. So there's no fetch handler at all: every request goes to
// the network as if there were no service worker, and nothing can be
// served stale after an update. (Browsers no longer need a fetch handler
// to install a web app.)
//
// It's a classic script, not a module, so every browser with Web Push can
// run it. Its URL is /sw.js, so its scope is the whole UI.

"use strict";

const ICON = "/ui/icon-192.png";
const BADGE = "/ui/badge-96.png";

// Limits on what a notification shows, whatever a message carries.
const MAX_TITLE = 200;
const MAX_BODY = 1000;
const MAX_TAG = 200;

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

// sameOrigin returns url if it's on origin, or origin's root if it isn't,
// or isn't a URL: a notification only ever opens the UI itself.
function sameOrigin(url, origin) {
  try {
    const u = new URL(String(url ?? "/"), origin);
    if (u.origin === origin && (u.protocol === "https:" || u.protocol === "http:")) return u.href;
  } catch {
    // Not a URL.
  }
  return new URL("/", origin).href;
}

// text returns v if it's a string, cut to n characters, or "".
function text(v, n) {
  return typeof v === "string" ? v.slice(0, n) : "";
}

// notificationFor returns the title and options for a pushed message, as
// doh sends it: {id, kind, title, body, tag, url, time}. Anything else
// still shows a notification, since a push must show one.
function notificationFor(message, origin) {
  const m = message && typeof message === "object" ? message : {};
  const tag = text(m.tag, MAX_TAG);
  const time = Date.parse(m.time);
  return {
    title: text(m.title, MAX_TITLE) || "doh",
    options: {
      body: text(m.body, MAX_BODY) || "Something on your network needs you. Open doh to see what.",
      icon: ICON,
      badge: BADGE,
      lang: "en",
      // A newer alert about the same thing replaces the last one.
      ...(tag ? { tag, renotify: true } : {}),
      timestamp: Number.isFinite(time) ? time : Date.now(),
      data: { url: sameOrigin(m.url, origin) },
    },
  };
}

self.addEventListener("push", (event) => {
  let message = null;
  try {
    message = event.data ? event.data.json() : null;
  } catch {
    // Not JSON: shown as a generic alert.
  }
  const { title, options } = notificationFor(message, self.location.origin);
  event.waitUntil(self.registration.showNotification(title, options));
});

// focusOrOpen focuses a window of the UI and shows url in it, or opens a
// new one.
async function focusOrOpen(url) {
  const origin = self.location.origin;
  const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  const ui = windows.find((c) => sameOrigin(c.url, origin) === c.url);
  if (!ui) return self.clients.openWindow(url);
  // Focus first, while the tap still counts as the user's.
  const focused = await ui.focus();
  if (ui.url !== url && typeof ui.navigate === "function") {
    try {
      return (await ui.navigate(url)) ?? focused;
    } catch {
      // Not controlled by this worker yet: it stays where it was.
    }
  }
  return focused;
}

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = sameOrigin(event.notification.data?.url, self.location.origin);
  event.waitUntil(focusOrOpen(url));
});
