// Motion: one vocabulary for things arriving, leaving, and moving, in
// the durations and curves app.css defines. It explains change; it never
// decorates, and for people who prefer reduced motion, it doesn't happen.

// reducedMotion reports whether someone prefers less motion.
export const reducedMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

// transition runs update, which changes the page, as a view transition
// where the browser has them: the old view fades and lifts away as the new
// one settles in. Elsewhere, or with reduced motion, it just runs it.
export function transition(update) {
  if (!document.startViewTransition || reducedMotion() || document.hidden) {
    update();
    return;
  }
  document.startViewTransition(update);
}

// enter marks el as just arrived, so it eases in, once.
export function enter(el) {
  if (reducedMotion()) return el;
  el.classList.add("arrive");
  el.addEventListener("animationend", () => el.classList.remove("arrive"), { once: true });
  return el;
}

// leave eases el out, then removes it.
export function leave(el) {
  if (reducedMotion() || !el.isConnected) { el.remove(); return; }
  el.classList.add("depart");
  el.addEventListener("animationend", () => el.remove(), { once: true });
  setTimeout(() => el.remove(), 500); // without animations, go anyway
}

// burst scatters sprinkles out of el's center: the celebration for a
// device connecting, and nothing else. Each sprinkle's direction, reach,
// tilt, and color are custom properties, set through the CSSOM, which the
// page's policy allows where style attributes aren't.
export function burst(el, count = 14) {
  if (reducedMotion()) return;
  const box = document.createElement("span");
  box.className = "burst";
  box.setAttribute("aria-hidden", "true");
  for (let i = 0; i < count; i++) {
    const s = document.createElement("span");
    s.className = "burst-sprinkle";
    const angle = (360 / count) * i + (i % 3) * 7;
    s.style.setProperty("--angle", `${angle}deg`);
    s.style.setProperty("--reach", `${3.2 + (i % 4) * 0.7}rem`);
    s.style.setProperty("--tilt", `${(i * 47) % 180}deg`);
    s.style.setProperty("--hue", ["var(--glaze)", "var(--dough)", "var(--info)", "var(--ok)"][i % 4]);
    box.append(s);
  }
  el.append(box);
  setTimeout(() => box.remove(), 1400);
}
