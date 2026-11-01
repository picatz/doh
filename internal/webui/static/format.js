// Formatting shared by the web UI, in the reader's own locale, kept
// apart from the page so it can be tested on its own.

const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
const date = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });

// units are those fromNow says times in, largest first, each with the
// least of it worth saying: months and years once there are two of them,
// so 45 days says "in 45 days" rather than "next month", and smaller
// units once there's one.
const units = [
  ["year", 365 * 864e5, 2],
  ["month", 30 * 864e5, 2],
  ["day", 864e5, 1],
  ["hour", 36e5, 1],
  ["minute", 6e4, 1],
];

// fromNow says when t is relative to now, to the nearest sensible unit:
// "in 3 days", "2 hours ago", "tomorrow", or "just now" within a minute.
// t is anything Date accepts.
export function fromNow(t, now = Date.now(), format = relative) {
  const ms = new Date(t).getTime() - now;
  if (Number.isNaN(ms)) return "";
  const abs = Math.abs(ms);
  if (abs < 6e4) return "just now";
  const [unit, size] = units.find(([, size, least]) => abs >= least * size) ?? units.at(-1);
  return format.format(Math.round(ms / size), unit);
}

// formatDate says the day t falls on, such as "Jan 30, 2027".
export function formatDate(t) {
  const d = new Date(t);
  return Number.isNaN(d.getTime()) ? "" : date.format(d);
}
