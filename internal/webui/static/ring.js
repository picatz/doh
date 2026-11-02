// The ring: a day of queries drawn as doh's donut. It's a 24-hour clock,
// midnight at the top and noon at the bottom. Each hour's glaze is as
// thick as its traffic, and every hour that blocked something carries
// sprinkles, more for more. Hours yet to come are a faint track.
//
// The geometry is pure and tested; drawing builds SVG with the DOM.

const SVG = "http://www.w3.org/2000/svg";

// Geometry, in the 240 by 240 view box.
export const SIZE = 240;
const C = SIZE / 2;
const INNER = 66; // the hole's edge
const THICK = 34; // the glaze at its fullest
const MIN = 7; // the glaze for an hour with any traffic at all
const GAP = 1.4; // degrees between hours

// angle returns the clock angle, in degrees clockwise from the top, of
// hour h of the day, which may be fractional.
export const angle = (h) => (((h % 24) + 24) % 24) * 15;

// point returns the view box coordinates at radius r and clock angle a.
export function point(r, a) {
  const rad = ((a - 90) * Math.PI) / 180;
  return [C + r * Math.cos(rad), C + r * Math.sin(rad)];
}

const f = (n) => Math.round(n * 100) / 100;

// sector returns the path of an annular sector from clock angle a0 to a1
// between radii r0 and r1.
export function sector(r0, r1, a0, a1) {
  const large = a1 - a0 > 180 ? 1 : 0;
  const [x0, y0] = point(r1, a0), [x1, y1] = point(r1, a1);
  const [x2, y2] = point(r0, a1), [x3, y3] = point(r0, a0);
  return `M${f(x0)} ${f(y0)}A${r1} ${r1} 0 ${large} 1 ${f(x1)} ${f(y1)}L${f(x2)} ${f(y2)}A${r0} ${r0} 0 ${large} 0 ${f(x3)} ${f(y3)}Z`;
}

// thickness returns how thick an hour's glaze is: by the square root of
// its share of the busiest hour, so quiet hours still show.
export function thickness(total, busiest) {
  if (!total || !busiest) return 0;
  return MIN + (THICK - MIN) * Math.sqrt(total / busiest);
}

// sprinkleCount returns how many sprinkles show an hour's blocked
// queries: one for any, then one more for each tenfold, at most four.
export const sprinkleCount = (blocked) => (blocked > 0 ? Math.min(4, 1 + Math.floor(Math.log10(blocked))) : 0);

// hash returns a small, stable number for a string, so sprinkles land in
// the same places on every render.
function hash(s) {
  let x = 2166136261;
  for (const c of s) x = Math.imul(x ^ c.codePointAt(0), 16777619);
  return (x >>> 0) / 4294967295;
}

// sprinkles returns where an hour's sprinkles go: within its sector, on
// its glaze, each with a tilt.
export function sprinkles(hour, blocked, glaze) {
  const n = sprinkleCount(blocked);
  const out = [];
  for (let i = 0; i < n; i++) {
    const t = hash(`${hour}:${i}`), u = hash(`${i}:${hour}`), v = hash(`${hour}-${i}-tilt`);
    const a = angle(hour) + GAP + (15 - 2 * GAP) * ((i + 0.2 + 0.6 * t) / n);
    const r = INNER + 4 + Math.max(0, glaze - 8) * u;
    out.push({ a, r, tilt: Math.round(v * 180) });
  }
  return out;
}

// hourOf returns the hour of the local clock a bucket starts at.
export const hourOf = (bucket) => new Date(bucket.start).getHours();

// hoursOf groups buckets by the hour of the clock they start at, adding
// up any that share one, as on the day clocks fall back and an hour
// happens twice. Each hour keeps its earliest start.
export function hoursOf(buckets) {
  const hours = new Map();
  for (const b of buckets) {
    const h = hourOf(b), seen = hours.get(h);
    hours.set(h, seen ? {
      start: seen.start,
      allowed: (seen.allowed || 0) + (b.allowed || 0),
      blocked: (seen.blocked || 0) + (b.blocked || 0),
      rewritten: (seen.rewritten || 0) + (b.rewritten || 0),
      errors: (seen.errors || 0) + (b.errors || 0),
    } : b);
  }
  return hours;
}

// totalOf returns how many queries a bucket counts.
export const totalOf = (b) => (b.allowed || 0) + (b.blocked || 0) + (b.rewritten || 0) + (b.errors || 0);

const el = (tag, attrs = {}) => {
  const e = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
  return e;
};

// drawRing draws a day. buckets are the day's hourly counts from local
// midnight; now is the current time. describe(bucket, hour) says an hour
// in words; open(bucket, hour) shows its queries. It returns the SVG.
export function drawRing(buckets, { now = new Date(), describe, open, label }) {
  const byHour = hoursOf(buckets);
  const busiest = Math.max(0, ...buckets.map(totalOf));
  const current = now.getHours() + now.getMinutes() / 60;

  const svg = el("svg", { viewBox: `0 0 ${SIZE} ${SIZE}`, class: "ring", role: "group", "aria-label": label });

  // The day's track: the dough beneath the glaze.
  svg.append(el("circle", { class: "ring-track", cx: C, cy: C, r: INNER + MIN / 2, fill: "none", "stroke-width": MIN }));

  // The hour marks, outside the ring.
  for (const [h, text] of [[0, "12a"], [6, "6a"], [12, "12p"], [18, "6p"]]) {
    const [x, y] = point(INNER + THICK + 14, angle(h));
    const t = el("text", { class: "ring-label", x: f(x), y: f(y), "text-anchor": "middle", "dominant-baseline": "central" });
    t.textContent = text;
    svg.append(t);
  }

  const hours = el("g", { class: "ring-hours" });
  svg.append(hours);
  const segments = [];
  for (let h = 0; h < 24; h++) {
    const b = byHour.get(h);
    const total = b ? totalOf(b) : 0;
    const future = h > Math.floor(current);
    const t = thickness(total, busiest);
    const g = el("g", {
      class: "ring-hour" + (future ? " future" : "") + (total ? "" : " empty") + (b?.blocked ? " blocked" : ""),
      role: "button", tabindex: -1,
      "aria-label": describe(b, h, future),
    });
    // Through the CSSOM: the page's CSP refuses style attributes.
    g.style.setProperty("--i", String(h));
    // A hit area across the whole sector, so thin hours are easy to point at.
    g.append(el("path", { class: "ring-hit", d: sector(INNER - 4, INNER + THICK + 6, angle(h), angle(h + 1)) }));
    if (t) g.append(el("path", { class: "ring-glaze", d: sector(INNER, INNER + t, angle(h) + GAP / 2, angle(h + 1) - GAP / 2) }));
    for (const s of sprinkles(h, b?.blocked || 0, t)) {
      const [x, y] = point(s.r, s.a);
      g.append(el("rect", { class: "ring-sprinkle", x: f(x - 3.2), y: f(y - 1.1), width: 6.4, height: 2.2, rx: 1.1, transform: `rotate(${s.tilt} ${f(x)} ${f(y)})` }));
    }
    if (!future && b) {
      g.addEventListener("click", () => open(b, h));
      g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(b, h); } });
    }
    hours.append(g);
    segments.push(g);
  }

  // Now, as a dot just outside the ring.
  const [nx, ny] = point(INNER + THICK + 4, angle(current));
  svg.append(el("circle", { class: "ring-now", cx: f(nx), cy: f(ny), r: 3.5 }));

  // One stop in the tab order; arrow keys move between hours.
  let at = Math.min(23, Math.floor(current));
  segments[at].setAttribute("tabindex", "0");
  svg.addEventListener("keydown", (e) => {
    const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1, Home: -at, End: Math.floor(current) - at }[e.key];
    if (step === undefined) return;
    e.preventDefault();
    segments[at].setAttribute("tabindex", "-1");
    at = Math.max(0, Math.min(23, at + step));
    segments[at].setAttribute("tabindex", "0");
    segments[at].focus();
  });
  return svg;
}
