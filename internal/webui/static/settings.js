// Settings: one hub for who you are, your household, automation, and the
// server, instead of a page of everything. A list of sections, and the
// chosen one: side by side on a wide screen, one after the other, with a
// way back, on a narrow one.
//
// Alerts and, when it comes, an audit trail of who changed what belong
// here, under Household and Server.

import { renderApiPanel } from "./accounts.js";
import { renderAlerts } from "./alerts.js";
import { api, report } from "./api.js";
import { $, plural } from "./dom.js";
import { renderServer } from "./overview.js";
import { renderAccountPanel, renderPeoplePanel } from "./people.js";
import { SETTINGS, settingsFor } from "./routes.js";
import { isAdmin, isOperator, state } from "./state.js";
import { renderTenants } from "./tenants.js";

// RENDER fills each section's panel.
const RENDER = {
  account: renderAccountPanel,
  people: renderPeoplePanel,
  alerts: renderAlerts,
  api: renderApiPanel,
  tenants: renderTenants,
  server: async () => {
    state.status = await api("GET", "/status");
    renderServer(state.status);
  },
};

let shown = "";

// visibleSections returns the sections the signed-in person sees.
const visibleSections = () => settingsFor({ operator: isOperator(), admin: isAdmin() });

// renderSettings shows section, or with none, the list of sections, and
// on a wide screen, the first of them beside it.
export async function renderSettings(section) {
  const view = $("view-settings");
  const sections = visibleSections();
  const ids = new Set(sections.map((s) => s.id));
  for (const a of view.querySelectorAll(".subnav-item[data-section]")) a.hidden = !ids.has(a.dataset.section);
  const chosen = ids.has(section) ? section : "";
  const open = chosen || sections[0].id;
  view.toggleAttribute("data-open", !!chosen);
  for (const a of view.querySelectorAll(".subnav-item[data-section]")) {
    if (a.dataset.section === open) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  for (const s of SETTINGS) $("panel-" + s.id).hidden = s.id !== open;
  shown = open;
  if (state.hints.people === undefined) {
    // Fill in what the list says of People and Alerts, once, alongside.
    api("GET", "/people").then((d) => { state.hints.people = (d?.people || []).length; renderHints(); }).catch(() => {});
  }
  if (state.hints.alerts === undefined && state.setup?.steps.some((x) => x.id === "alerts")) state.hints.alerts = state.setup.destinations.length;
  renderHints();
  await RENDER[open]();
  renderHints();
}

// refreshSettings renders the shown section again, after a change.
export async function refreshSettings() {
  if (shown) await RENDER[shown]().catch(report);
  renderHints();
}

// settingsTitle names a section, for the page's title.
export const settingsTitle = (section) => SETTINGS.find((s) => s.id === section)?.title || "Settings";

// renderHints says, under each section's name, what it holds, where
// that's known without asking the server for more.
function renderHints() {
  const s = state.auth?.session;
  const hint = (id, text) => { const el = $("hint-" + id); if (el) el.textContent = text ?? ""; };
  hint("account", s?.person ? s.name : "Signed in with a link");
  hint("people", state.hints.people === undefined ? "" : state.hints.people ? plural(state.hints.people, "person", "people") : "No one yet");
  hint("alerts", state.hints.alerts === undefined ? "" : state.hints.alerts ? plural(state.hints.alerts, "destination") : "Off: nowhere to send them");
  hint("api", state.hints.api === undefined ? "" : state.hints.api ? plural(state.hints.api, "account") : "None");
  hint("tenants", state.tenants.length ? plural(state.tenants.length, "tenant") : "None");
  hint("server", state.hints.server || "");
  hint("setup", state.hints.setup || "");
}
