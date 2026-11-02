// Watching for a device to connect: after a setup link is made, the UI
// asks the server, politely, whether the device has asked it anything
// yet, and stops once it has, the link expires, or no one is looking.
// Timing and the loop are here, apart from the page, so they're tested.

// SETUP_LINK_TTL is how long a setup link works, as the server sets it.
export const SETUP_LINK_TTL = 30 * 60e3;

// pollDelay returns how long to wait before asking again, in ms, after
// attempt tries: every two seconds for the first half minute, when a
// device is most likely to appear, then backing off to every ten.
export function pollDelay(attempt) {
  if (attempt < 15) return 2000;
  return Math.min(10_000, Math.round(2000 * 1.25 ** (attempt - 14)));
}

// linkSince returns when a setup link was made, by the server's clock,
// from when it expires, less a minute for clocks and in-flight queries:
// the time to ask about devices since. Using the server's own times keeps
// a browser with a wrong clock from missing the moment.
export const linkSince = (expires, ttl = SETUP_LINK_TTL) => new Date(new Date(expires).getTime() - ttl - 60e3);

// deviceQuery returns what to ask /devices for: the named device seen
// since the link was made, or with no name, any device on the profile
// first seen since then.
export function deviceQuery(profile, device, since) {
  const q = { profile, since: since.toISOString() };
  if (device) q.device = device;
  else q.new = "true";
  return q;
}

// watch asks fetch(query) for devices until one appears, then returns
// it. It returns null if signal aborts, or once until passes. sleep(ms,
// signal) waits; now() is the time. Errors from fetch are retried, as a
// server restarting shouldn't end the wait.
export async function watch({ query, fetch, until, signal, sleep, now = () => Date.now(), onTick = () => {} }) {
  for (let attempt = 0; ; attempt++) {
    if (signal?.aborted || now() > until) return null;
    try {
      const data = await fetch(query);
      const found = data?.devices?.[0];
      if (found) return found;
    } catch (err) {
      if (err?.name === "AbortError") return null;
    }
    onTick(attempt);
    await sleep(pollDelay(attempt), signal);
  }
}

// sleep waits ms, or until signal aborts.
export function sleep(ms, signal) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => { clearTimeout(t); resolve(); }, { once: true });
  });
}
