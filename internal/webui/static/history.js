// Change history: who changed what, from the server's audit trail, newest
// first, a page at a time as someone scrolls. Only admins see it; the
// server shows each tenant only its own changes.

import { api, APIError, report } from "./api.js";
import { ACTIONS, actorsOf, dayLabel, describe } from "./audit.js";
import { $, clear, emptyState, h, icon } from "./dom.js";
import { fromNow } from "./format.js";
import { isAdmin, isOperator, tenantName } from "./state.js";

const PAGE = 50;

// filter is what the history is narrowed to; actors, who has been seen
// making changes, for choosing among them.
const filter = { actor: "", action: "" };
let actors = [];
let next = "";
let loading = null;
let observer = null;

// renderHistory shows the first page of changes, and the filters.
export async function renderHistory() {
  if (!isAdmin()) return;
  renderFilters();
  await loadHistory(true);
}

function renderFilters() {
  const action = h("select", { "aria-label": "Kind of change" }, ACTIONS.map(([id, name]) => h("option", { value: id, text: name })));
  action.value = filter.action;
  action.addEventListener("change", () => { filter.action = action.value; loadHistory(true).catch(report); });
  const actor = h("select", { "aria-label": "Made by" },
    h("option", { value: "", text: "Anyone" }),
    actors.map((a) => h("option", { value: a.key, text: a.name })));
  actor.value = filter.actor;
  actor.addEventListener("change", () => { filter.actor = actor.value; loadHistory(true).catch(report); });
  clear($("history-filters")).append(
    h("label", {}, h("span", { text: "Show" }), action),
    h("label", {}, h("span", { text: "Made by" }), actor));
}

// loadHistory loads the first page of changes, or with fresh false, the
// next one, adding it below.
export function loadHistory(fresh) {
  if (loading && !fresh) return loading;
  const list = $("history");
  const more = $("history-more");
  if (fresh) next = "";
  const query = { limit: PAGE, actor: filter.actor, action: filter.action, page_token: fresh ? "" : next };
  const mine = loading = (async () => {
    more.disabled = true;
    list.setAttribute("aria-busy", "true");
    if (fresh && !list.querySelector(".history-item")) clear(list).append(h("li", { class: "history-loading muted", text: "Loading changes…" }));
    try {
      const page = await api("GET", "/audit", { query });
      if (mine !== loading) return;
      if (fresh) clear(list);
      const known = actors.length;
      actors = actorsOf(page.events, actors);
      if (actors.length !== known) renderFilters();
      appendEvents(list, page.events);
      next = page.next_page_token || "";
      if (!list.childElementCount) {
        list.append(h("li", {}, emptyState({
          compact: true, mood: "calm",
          title: filter.actor || filter.action ? "No changes like that." : "No changes yet.",
          body: "Changes to profiles, people, alerts, and the rest show up here, saying who made them.",
        })));
      }
    } catch (err) {
      if (mine !== loading) return;
      clear(list).append(h("li", { class: "muted", text: err instanceof APIError && err.status === 404 ? "The change history needs the server to run with a data directory (--data-dir)." : err.message }));
      next = "";
    } finally {
      if (mine === loading) {
        loading = null;
        list.removeAttribute("aria-busy");
        more.hidden = !next;
        more.disabled = false;
        watchEnd(more);
      }
    }
  })();
  return mine;
}

// appendEvents adds events to list, under a heading for each new day.
function appendEvents(list, events) {
  let day = list.querySelector("li.history-day:last-of-type")?.dataset.day || "";
  for (const e of events) {
    const label = dayLabel(e.time);
    if (label !== day) {
      day = label;
      list.append(h("li", { class: "history-day", "data-day": label }, h("h4", { text: label })));
    }
    list.append(eventRow(e));
  }
}

// eventRow says what e changed, with its facts one click away.
function eventRow(e) {
  const at = new Date(e.time);
  const meta = [
    h("time", { datetime: e.time, title: `${at.toLocaleString()}, ${fromNow(e.time)}`, text: at.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" }) }),
  ];
  if (isOperator() && e.tenant) meta.push(h("span", { class: "badge tenant", text: tenantName(e.tenant) }));
  if (e.actor?.via) meta.push(h("span", { class: "muted", text: `by ${e.actor.via}` }));
  const head = [h("span", { class: "history-what", text: describe(e) }), h("span", { class: "history-meta" }, ...meta)];
  const details = Object.entries(e.details || {});
  if (!details.length) return h("li", { class: "history-item" }, ...head);
  return h("li", { class: "history-item" },
    h("details", {},
      h("summary", {}, h("span", { class: "history-head" }, ...head), icon("chevron-right", "chevron")),
      h("dl", { class: "kv history-details" },
        h("dt", { text: "Action" }), h("dd", {}, h("code", { text: e.action })),
        details.flatMap(([k, v]) => [h("dt", { text: k }), h("dd", { text: v })]))));
}

// watchEnd loads the next page when the "Show older" button scrolls into
// view, so the history reads as one list; the button still works alone.
function watchEnd(more) {
  if (!("IntersectionObserver" in globalThis)) return;
  observer ??= new IntersectionObserver((entries) => {
    if (entries.some((x) => x.isIntersecting) && next && !$("panel-audit").hidden) loadHistory(false).catch(report);
  }, { rootMargin: "200px" });
  observer.disconnect();
  if (next) observer.observe(more);
}
