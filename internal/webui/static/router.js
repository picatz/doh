import { setLogFilter, loadLogs, stopLive, closeDrawer } from "./activity.js";
import { report } from "./api.js";
import { $ } from "./dom.js";
import { runExplain } from "./explain.js";
import { renderOverview } from "./overview.js";
import { renderSecurity } from "./people.js";
import { renderProfiles, section } from "./profiles.js";
import { state, isOperator } from "./state.js";
import { renderTenants } from "./tenants.js";

export const VIEWS = ["overview", "profiles", "logs", "explain", "security", "tenants"];

// parseRoute reads the view and its argument, such as a profile ID, from
// a URL hash.
export function parseRoute(hash = location.hash) {
  const m = /^#\/([a-z]+)(?:\/([^?]*))?(?:\?(.*))?$/.exec(hash);
  if (!m || !VIEWS.includes(m[1])) return { view: "overview", arg: "", query: new URLSearchParams() };
  let arg = "";
  try { arg = decodeURIComponent(m[2] || ""); } catch { /* a malformed link: ignore its argument */ }
  return { view: m[1], arg, query: new URLSearchParams(m[3] || "") };
}

// routeHash returns the URL hash of a view, its argument, and its query,
// leaving out empty query values.
export function routeHash(view, arg = "", query = {}) {
  const q = new URLSearchParams(Object.entries(query).filter(([, v]) => v !== undefined && v !== ""));
  return `#/${view}${arg ? "/" + encodeURIComponent(arg) : ""}${q.size ? "?" + q : ""}`;
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

// applyRoute shows what the URL names.
export function applyRoute() {
  const { view, arg, query } = parseRoute();
  if (!location.hash) setRoute(view, arg);
  if (view === "profiles") {
    if (state.selected !== arg) state.profileTab = "";
    state.selected = arg;
    state.profileTab = query.get("tab") || state.profileTab;
  }
  if (view === "logs") setLogFilter(query);
  show(view);
}

export function show(view) {
  if (view === "tenants" && !isOperator()) view = "overview";
  const changed = state.view !== view;
  state.view = view;
  for (const b of document.querySelectorAll(".nav")) {
    if (b.dataset.view === view) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  }
  for (const v of VIEWS) $("view-" + v).hidden = v !== view;
  const section = $("view-" + view);
  if (changed) {
    section.classList.remove("entering");
    void section.offsetWidth; // restart the entrance
    section.classList.add("entering");
    window.scrollTo({ top: 0 });
    document.title = `${section.querySelector("h2")?.textContent || "doh"} · doh`;
  }
  closeDrawer();
  if (view !== "logs") stopLive();
  const load = { overview: renderOverview, profiles: renderProfiles, logs: () => loadLogs(true), explain: () => { if (!$("explain-result").childElementCount) runExplain(); }, security: renderSecurity, tenants: renderTenants }[view];
  Promise.resolve(load()).catch(report);
}
