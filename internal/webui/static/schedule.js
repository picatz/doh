// Schedules, as people read them and as the server applies them. Pure
// functions with no DOM, so they're tested on their own.

// WEEKDAYS are the day names schedules use, from Sunday, as
// Date.prototype.getDay counts them.
export const WEEKDAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

// DAY_NAMES are each day's full name, for labels.
export const DAY_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

const SHORT = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

// DAY_PRESETS are common sets of days.
export const DAY_PRESETS = [
  ["Every day", WEEKDAYS],
  ["Weekdays", ["mon", "tue", "wed", "thu", "fri"]],
  ["School nights", ["sun", "mon", "tue", "wed", "thu"]],
];

// clockMinutes parses a time of day as "HH:MM" into minutes since
// midnight, or NaN.
export function clockMinutes(hhmm) {
  const m = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(hhmm || "");
  return m ? Number(m[1]) * 60 + Number(m[2]) : NaN;
}

// overnight reports whether a schedule ends before it starts, running past
// midnight into the next morning.
export const overnight = (sc) => clockMinutes(sc.end) < clockMinutes(sc.start);

// scheduleActive reports whether schedule sc is in effect at the instant
// now in the IANA timeZone, as the server decides it: on its days (every
// day if it has none), from its start until its end, where a period that
// ends before it starts runs past midnight and belongs to the day it
// started on, so a Sunday 21:00–07:00 bedtime covers Monday 06:00.
//
// It returns null when that can't be known: without a time zone, the
// server's own applies, which the browser can't see.
export function scheduleActive(sc, now, timeZone) {
  if (!timeZone) return null;
  let parts;
  try {
    parts = new Intl.DateTimeFormat("en-US", { timeZone, weekday: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(now);
  } catch {
    return null; // a time zone this browser doesn't know
  }
  const part = (type) => parts.find((p) => p.type === type)?.value || "";
  const day = WEEKDAYS.indexOf(part("weekday").slice(0, 3).toLowerCase());
  const minute = (Number(part("hour")) % 24) * 60 + Number(part("minute"));
  const start = clockMinutes(sc.start);
  const end = clockMinutes(sc.end);
  if (day < 0 || [minute, start, end].some(Number.isNaN)) return null;

  const on = (d) => !sc.days?.length || sc.days.includes(WEEKDAYS[(d + 7) % 7]);
  if (start === end) return on(day); // all day
  if (start < end) return on(day) && start <= minute && minute < end;
  return (on(day) && minute >= start) || (on(day - 1) && minute < end);
}

// formatPeriod describes a schedule's times, as "21:00–07:00", or "all
// day" when it ends when it starts.
export function formatPeriod(sc) {
  return sc.start === sc.end ? "all day" : `${sc.start}–${sc.end}`;
}

// formatDays describes days compactly, as "Every day", "Mon–Fri", or
// "Sat, Sun": runs of consecutive days, wrapping around the week.
export function formatDays(days) {
  const set = WEEKDAYS.map((d) => !days?.length || days.includes(d));
  if (set.every(Boolean)) return "Every day";
  // Start at a day that begins a run, so runs past Saturday stay whole.
  const first = Math.max(0, set.findIndex((on, i) => on && !set[(i + 6) % 7]));
  const runs = [];
  for (let k = 0; k < 7;) {
    const i = (first + k) % 7;
    if (!set[i]) { k++; continue; }
    let n = 0;
    while (n + k < 7 && set[(i + n) % 7]) n++;
    const from = SHORT[i];
    const to = SHORT[(i + n - 1) % 7];
    runs.push(...(n === 1 ? [from] : n === 2 ? [from, to] : [`${from}–${to}`]));
    k += n;
  }
  return runs.join(", ");
}

// describeBlocks says what a schedule blocks, naming services and lists
// with names(kind, id), where kind is "service" or "list".
export function describeBlocks(sc, names = (_, id) => id) {
  if (sc.block_all) {
    return sc.allow?.length ? `everything except ${sc.allow.join(", ")}` : "everything";
  }
  return [
    ...(sc.services || []).map((id) => names("service", id)),
    ...(sc.lists || []).map((id) => names("list", id)),
    ...(sc.deny || []),
  ].join(", ") || "nothing";
}
