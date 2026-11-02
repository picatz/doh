// The change history's words: who changed what, from the server's audit
// trail (GET /audit), said the way a person would. Pure, so it's tested
// on its own; history.js shows it.

// ACTIONS are the kinds of change to filter by: an action prefix, which
// the server matches with everything under it, and a name for people.
export const ACTIONS = [
  ["", "All changes"],
  ["profile", "Profiles"],
  ["alerts", "Alerts"],
  ["person", "People and passkeys"],
  ["signin_link", "Sign-in links"],
  ["setup_link", "Setup links"],
  ["service_account", "Service accounts"],
  ["tenant", "Tenants"],
  ["policy", "Server policy"],
];

// VERBS begin the server's summaries; after a name, they're lower case.
const VERBS = /^(Added|Allowed|Blocked|Changed|Confirmed|Created|Deleted|Denied|Made|Removed|Revoked|Rotated|Stopped|Unblocked|Unsubscribed)\b/;

const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");

// plainSummary drops what only programs need from a summary: an ID in
// parentheses after the name it's made from ("TikTok (tiktok)"), and
// "profile" before a profile's name.
export function plainSummary(summary) {
  const s = String(summary || "");
  const dropped = s.replace(/ \(([a-z0-9][a-z0-9_-]*)\)/g, (m, id, at) => {
    const words = s.slice(0, at).split(" ");
    for (let n = 1; n <= Math.min(4, words.length); n++) {
      if (slug(words.slice(-n).join(" ")) === id) return "";
    }
    return m;
  });
  return dropped.replace(/ in profile /g, " in ");
}

// actorName names who made a change, as the start of a sentence.
export function actorName(actor = {}) {
  switch (actor.kind) {
    case "person": return actor.name || "Someone";
    case "service_account": return actor.name ? `${actor.name} (a service account)` : "A service account";
    case "token": return actor.name ? `The ${actor.name}` : "An API token";
    case "link": return "Someone (signed in with a link)";
    case "recipient": return "The email's recipient";
    default: return actor.name || "Someone";
  }
}

// describe says what an event did, as a sentence: "Alex unblocked TikTok
// in Kids".
export function describe(e) {
  const who = actorName(e.actor);
  const what = plainSummary(e.summary);
  if (!what) return `${who}: ${e.action}`;
  return `${who} ${VERBS.test(what) ? what[0].toLowerCase() + what.slice(1) : what}`;
}

// dayLabel names the day t falls on, relative to now: "Today",
// "Yesterday", or its date.
export function dayLabel(t, now = new Date(), format = new Intl.DateTimeFormat(undefined, { weekday: "long", month: "short", day: "numeric" })) {
  const d = new Date(t);
  const start = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const days = Math.round((start(now) - start(d)) / 864e5);
  if (days === 0) return "Today";
  if (days === 1) return "Yesterday";
  return format.format(d);
}

// actorsOf returns the distinct actors of events, by the name the server
// filters on, in the order first seen.
export function actorsOf(events, known = []) {
  const out = [...known];
  for (const e of events) {
    const key = e.actor?.id || e.actor?.name;
    if (key && !out.some((a) => a.key === key)) out.push({ key, name: actorName(e.actor) });
  }
  return out;
}
