// The router: shows what the URL names. Views register what they render;
// routes.js says what the URLs are.

import { closeDrawer } from "./activity.js";
import { report } from "./api.js";
import { $ } from "./dom.js";
import { transition } from "./motion.js";
import { parseRoute, routeHash, VIEWS } from "./routes.js";
import { state } from "./state.js";

export { routeHash };

// views holds each view's { title(arg), route(arg, query), render(arg,
// query), leave() }, by name.
const views = new Map();

// register adds a view.
export function register(name, view) {
  views.set(name, view);
}

// go navigates to a view, adding to history.
export function go(view, arg = "", query = {}) {
  const hash = routeHash(view, arg, query);
  if (location.hash === hash) applyRoute();
  else location.hash = hash;
}

// setRoute records where the page is without rendering again, such as
// after creating a profile that's already shown.
export function setRoute(view, arg = "", query = {}) {
  history.replaceState(null, "", routeHash(view, arg, query));
}

// where is the place last shown, so a change within a view, such as to
// another settings section, is told apart from moving to another view.
let where = { view: "", arg: "", first: true };

// applyRoute shows what the URL names. Old URLs, such as #/security, are
// replaced with where those things are now.
export function applyRoute() {
  const r = parseRoute(location.hash);
  if (!location.hash || r.moved) setRoute(r.view, r.arg, Object.fromEntries(r.query));
  show(r.view, r.arg, r.query);
}

// show shows view, with its argument and query.
export function show(name, arg = "", query = new URLSearchParams()) {
  let view = views.get(name);
  if (!view || (view.allowed && !view.allowed(arg))) { name = "overview"; view = views.get(name); arg = ""; }
  const prev = where;
  const changed = prev.view !== name;
  const moved = changed || prev.arg !== arg;
  where = { view: name, arg, first: false };
  state.view = name;
  view.route?.(arg, query);

  const update = () => {
    if (changed) views.get(prev.view)?.leave?.();
    for (const b of document.querySelectorAll(".nav")) {
      if (b.dataset.view === name || (name === "setup" && b.dataset.view === "overview")) b.setAttribute("aria-current", "page");
      else b.removeAttribute("aria-current");
    }
    for (const v of VIEWS) $("view-" + v).hidden = v !== name;
    if (changed) scrollTo({ top: 0 });
    closeDrawer();
    const rendering = Promise.resolve().then(() => view.render(arg, query)).catch(report);
    // Wait a moment for the view's data, so the transition shows it
    // arriving, but never long: a slow server shouldn't freeze the page.
    return Promise.race([rendering, new Promise((r) => setTimeout(r, 160))]);
  };
  if (changed && !prev.first) transition(update);
  else update();

  const title = view.title?.(arg) || "doh";
  document.title = `${title} · doh`;
  if (moved && !prev.first) {
    // Tell assistive technology where it is, and start the keyboard there.
    $("announcer").textContent = title;
    requestAnimationFrame(() => view.focus?.(arg)?.focus({ preventScroll: true }));
  }
}

// currentArg returns the shown view's argument, such as a profile ID.
export const currentArg = () => where.arg;
