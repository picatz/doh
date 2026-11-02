import { checkName } from "./activity.js";
import { api } from "./api.js";
import { $, buddy, clear, fmtDuration, fmtNum, fmtTime, h, icon, plural } from "./dom.js";
import { fromNow } from "./format.js";
import { drawRing, hoursOf, totalOf } from "./ring.js";
import { go } from "./router.js";
import { routeHash } from "./routes.js";
import { setReadOnly } from "./session.js";
import { isOperator, state, tenantName } from "./state.js";

// SECURITY_REASONS are the checks that stop attacks rather than apply
// someone's preferences, so the Overview can count threats apart.
export const SECURITY_REASONS = new Set(["homograph", "tunneling", "rebinding", "newly-registered", "bypass"]);

// startOfToday returns local midnight.
export function startOfToday(now = new Date()) {
  return new Date(now.getFullYear(), now.getMonth(), now.getDate());
}

// hourRange describes an hour of the clock, such as "7–8 PM".
export function hourRange(h) {
  const fmt = new Intl.DateTimeFormat(undefined, { hour: "numeric" });
  const at = (x) => fmt.format(new Date(2000, 0, 1, x));
  return `${at(h)}–${at((h + 1) % 24)}`;
}

// renderOverview shows today: the day as a ring, a plain verdict, what
// needs someone, and where queries went. Every number opens the queries
// behind it.
export async function renderOverview() {
  const midnight = startOfToday();
  const since = midnight.toISOString();
  const [status, stats] = await Promise.all([
    api("GET", "/status"),
    api("GET", "/stats", { query: { top: 6, since, interval: "1h" } }),
  ]);
  state.status = status;
  setReadOnly(status.policy);

  $("overview-date").textContent = new Intl.DateTimeFormat(undefined, { weekday: "long", month: "long", day: "numeric" }).format(midnight);

  const total = stats.total || 0;
  const by = stats.by_status || {};
  const blocked = by.blocked || 0, errors = by.error || 0;
  const threats = Object.entries(stats.by_reason || {}).reduce((n, [r, c]) => n + (SECURITY_REASONS.has(r) ? c : 0), 0);
  const today = (extra = {}) => ["logs", "", { since, ...extra }];
  const link = (text, route, cls = "") => h("a", { class: cls, href: routeHash(...route), text });

  // The ring, and its center, which follows the hour pointed at.
  const figure = $("ring-figure"), caption = $("ring-caption");
  const resting = () => { figure.textContent = fmtNum(total); caption.textContent = total === 1 ? "query today" : "queries today"; };
  const describe = (b, hr, future) => {
    if (future) return `${hourRange(hr)}: later today`;
    if (!b || !totalOf(b)) return `${hourRange(hr)}: no queries`;
    return `${hourRange(hr)}: ${plural(totalOf(b), "query", "queries")}${b.blocked ? `, ${fmtNum(b.blocked)} blocked` : ""}. Open them.`;
  };
  const ring = drawRing(stats.timeline || [], {
    label: `Today, hour by hour: ${plural(total, "query", "queries")}, ${fmtNum(blocked)} blocked. Use the arrow keys to move between hours.`,
    describe,
    open: (b, hr) => {
      const start = new Date(b.start), end = new Date(start.getTime() + 36e5);
      go("logs", "", { since: start.toISOString(), until: end.toISOString(), status: b.blocked ? "blocked" : "" });
    },
  });
  const hours = hoursOf(stats.timeline || []);
  ring.addEventListener("pointerover", (e) => showHour(e.target.closest(".ring-hour")));
  ring.addEventListener("focusin", (e) => showHour(e.target.closest(".ring-hour")));
  ring.addEventListener("pointerleave", resting);
  ring.addEventListener("focusout", resting);
  function showHour(g) {
    if (!g) return;
    const hr = Number(g.style.getPropertyValue("--i"));
    const b = hours.get(hr);
    const n = b ? totalOf(b) : 0;
    figure.textContent = g.classList.contains("future") ? "—" : fmtNum(n);
    caption.textContent = `${hourRange(hr)}${b?.blocked ? ` · ${fmtNum(b.blocked)} blocked` : ""}`;
  }
  clear($("ring")).append(ring);
  resting();

  // The verdict, in plain words, and what it rests on.
  const problems = attentionItems(status, stats, since);
  const verdict = clear($("verdict"));
  const summary = clear($("summary"));
  if (problems.length) {
    verdict.className = "verdict warn";
    verdict.append(icon("warn"), `${plural(problems.length, "thing needs", "things need")} you`);
  } else if (!total) {
    verdict.className = "verdict quiet";
    verdict.append(icon("overview"), "Waiting for the first query");
  } else {
    verdict.className = "verdict ok";
    verdict.append(icon("security"), "Protected");
  }
  if (total) {
    summary.append(
      link(plural(total, "query", "queries"), today()), ` so far today from ${plural(stats.clients || 0, "device")}. `,
      blocked ? `${fmtNum(blocked)} blocked (${((blocked / total) * 100).toFixed(blocked / total < 0.1 ? 1 : 0)}%)` : "Nothing blocked",
      threats ? `, ${fmtNum(threats)} of them by security protections.` : ".",
    );
  } else {
    summary.append("Nothing has asked this server for a name since midnight. ",
      link("Connect a device", ["profiles", state.profiles[0]?.id || ""]), " to start.");
  }

  const metric = (label, value, route, cls = "") => h("a", { class: "metric " + cls, href: routeHash(...route) },
    h("span", { class: "metric-value", text: fmtNum(value) }), h("span", { class: "metric-label", text: label }));
  clear($("metrics")).append(...[
    metric("blocked", blocked, today({ status: "blocked" }), blocked ? "glaze" : ""),
    threats ? metric("threats stopped", threats, today({ status: "blocked" }), "glaze") : null,
    metric(stats.clients === 1 ? "device" : "devices", stats.clients || 0, today()),
    errors ? metric("failed", errors, today({ status: "error" }), "warn") : null,
  ].filter(Boolean));

  // What needs someone, or a calm word that nothing does.
  const attention = clear($("attention"));
  if (problems.length) {
    attention.append(h("div", { class: "card attention-list" },
      h("div", { class: "attention-head" }, buddy("alert"), h("h3", { text: "Needs your attention" })),
      h("ul", {}, problems.map((p) => h("li", {}, icon("warn"), h("div", {}, h("strong", { text: p.title }), h("p", { class: "muted", text: p.detail })), p.action ? link(p.action[0], p.action[1], "button small") : null)))));
  } else if (total) {
    attention.append(h("div", { class: "all-good" }, buddy("calm"), h("span", {}, h("strong", { text: "Nothing needs you." }), " doh is quietly doing its job.")));
  }

  // Where things went.
  const rank = (el, items, route, unit, empty) => {
    clear(el);
    if (!items.length) { el.append(h("li", { class: "muted rank-empty", text: empty })); return; }
    const max = Math.max(...items.map((c) => c.count));
    for (const c of items) {
      const bar = h("span", { class: "rank-bar" });
      bar.style.setProperty("--share", (c.count / max).toFixed(3));
      const body = [h("span", { class: "rank-name", text: c.label || c.name, title: c.name }), h("span", { class: "rank-count", text: fmtNum(c.count), "aria-label": plural(c.count, unit) }), bar];
      el.append(h("li", {}, route ? h("a", { class: "rank-row", href: routeHash(...route(c)) }, ...body) : h("div", { class: "rank-row" }, ...body)));
    }
  };
  rank($("top-blocked"), stats.top_blocked || [], (c) => today({ status: "blocked", q: c.name }), "time", "Nothing blocked today.");
  const reasons = Object.entries(stats.by_reason || {}).filter(([r]) => r !== "rewrite").sort((x, y) => y[1] - x[1]).slice(0, 6).map(([name, count]) => ({ name, label: checkName(name), count }));
  rank($("by-reason"), reasons, (c) => today({ status: "blocked", reason: c.name }), "query", "Nothing blocked today.");
  rank($("top-clients"), stats.top_clients || [], null, "query", "No devices yet today.");

  renderServer(status);
}

// attentionItems lists what needs someone today, each with what to do.
export function attentionItems(status, stats, since) {
  const items = [];
  const operator = isOperator();
  if (status.policy?.error) {
    items.push({ title: "The policy file has a problem", detail: status.policy.error });
  }
  for (const l of status.lists || []) {
    if (l.error) items.push({ title: `The ${l.name} list didn't load`, detail: `${l.error}. Its domains aren't blocked until it does.` });
  }
  const errors = stats.by_status?.error || 0;
  if (errors) {
    const where = operator && status.upstreams?.length ? ` (${status.upstreams.join(", ")})` : "";
    items.push({
      title: `${plural(errors, "query", "queries")} failed today`,
      detail: operator
        ? `doh couldn't get answers from its upstream resolvers${where}. Check this server can reach them.`
        : "The server couldn't get answers for them. If it keeps happening, tell the server's operator.",
      action: ["See them", ["logs", "", { since, status: "error" }]],
    });
  }
  return items;
}

// renderServer fills in the details of how the server runs: everything
// for the operator, and a tenant's own corner for a tenant.
export function renderServer(status) {
  const info = clear($("server-info"));
  const kv = (k, v) => info.append(h("dt", { text: k }), h("dd", {}, v));
  if (!isOperator()) {
    $("server-title").textContent = $("server-nav-label").textContent = "Your tenant";
    state.hints.server = tenantName(status.tenant);
    $("server-link").textContent = "";
    kv("Tenant", tenantName(status.tenant));
    kv("Profiles", fmtNum(status.policy?.profiles));
    kv("Activity", status.query_log?.enabled ? "kept" : "off");
    kv("Version", status.version || "—");
    return;
  }
  const up = status.started ? fmtDuration(Date.now() - new Date(status.started)) : "";
  const failed = (status.lists || []).filter((l) => l.error).length;
  const summary = [up && `Up ${up}`, `${plural((status.lists || []).length, "list")}${failed ? `, ${failed} failed` : ""}`, status.version].filter(Boolean).join(" · ");
  state.hints.server = summary;
  $("server-link").textContent = `Server: ${summary}`;
  kv("Version", status.version || "—");
  kv("Up for", up || "—");
  for (const [k, v] of Object.entries(status.listeners || {})) kv(`Listening (${k})`, h("span", { class: "mono", text: v }));
  kv("Upstreams", h("span", { class: "mono", text: (status.upstreams || []).join(", ") || "—" }));
  kv("Policy", status.policy?.source || "flags");
  if (status.policy?.error) kv("Policy error", h("span", { class: "error", text: status.policy.error }));
  const ql = status.query_log || {};
  kv("Activity", ql.enabled ? `${fmtNum(ql.entries)} queries in memory${ql.dir ? `, kept ${ql.retention} on disk` : ""}` : "off");
  if (status.queries) kv("Since start", `${plural(status.queries.total, "query", "queries")}, ${fmtNum(status.queries.cached)} from cache`);

  const rows = clear($("list-health"));
  if (!status.lists?.length) rows.append(h("tr", {}, h("td", { colspan: 4, class: "muted", text: "No blocklists in use." })));
  for (const l of status.lists || []) {
    const st = l.error ? h("span", { class: "pill blocked", title: l.error }, icon("x"), "failed")
      : l.loading ? h("span", { class: "pill rewritten" }, "loading")
      : h("span", { class: "pill allowed" }, icon("check"), "loaded");
    rows.append(h("tr", {},
      h("td", {}, h("div", { text: l.name }), h("div", { class: "muted mono small", text: l.location })),
      h("td", { class: "num", text: fmtNum(l.rules) }),
      h("td", { text: l.loaded ? fromNow(l.loaded) : "—", title: fmtTime(l.loaded, true) }),
      h("td", {}, st, l.error && h("div", { class: "muted", text: l.error })),
    ));
  }
}

