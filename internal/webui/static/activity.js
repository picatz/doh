import { api, report } from "./api.js";
import { serviceName, listTitle } from "./apps.js";
import { $, h, icon, clear, edit, toast, fmtTime } from "./dom.js";
import { runExplain } from "./explain.js";
import { domainAction } from "./profiles.js";
import { go, setRoute } from "./router.js";
import { state, profile } from "./state.js";

export const LIVE_CAP = 500;

// logFilter returns the Activity view's filter: what its form says, and
// the time window and reason a link narrowed it to.
export function logFilter() {
  return {
    profile: $("f-profile").value,
    status: document.querySelector('input[name="f-status"]:checked')?.value || "",
    q: $("f-q").value.trim(),
    client: $("f-client").value.trim(),
    since: state.logScope.since,
    until: state.logScope.until,
    reason: state.logScope.reason,
  };
}

// setLogFilter fills the Activity view's filter from a URL's query.
export function setLogFilter(q) {
  $("f-profile").value = q.get("profile") || "";
  const status = q.get("status") || "";
  for (const r of document.querySelectorAll('input[name="f-status"]')) r.checked = r.value === status;
  $("f-q").value = q.get("q") || "";
  $("f-client").value = q.get("client") || "";
  // Filters beyond search and status open when a link uses them.
  if (q.get("profile") || q.get("client")) $("more-filters").open = true;
  const valid = (t) => (t && !Number.isNaN(Date.parse(t)) ? t : "");
  state.logScope = { since: valid(q.get("since")), until: valid(q.get("until")), reason: q.get("reason") || "" };
  renderLogScope();
}

// renderLogScope shows what a link narrowed the Activity view to, each
// with a way to widen it again.
export function renderLogScope() {
  const { since, until, reason } = state.logScope;
  const chips = [];
  if (since || until) {
    const fmt = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });
    const day = new Intl.DateTimeFormat(undefined, { weekday: "short", month: "short", day: "numeric" });
    const text = since && until ? `${day.format(new Date(since))}, ${fmt.format(new Date(since))}–${fmt.format(new Date(until))}`
      : since ? `Since ${day.format(new Date(since))}, ${fmt.format(new Date(since))}` : `Until ${fmt.format(new Date(until))}`;
    chips.push(["time", text, () => { state.logScope.since = state.logScope.until = ""; }]);
  }
  if (reason) chips.push(["reason", `Why: ${checkName(reason)}`, () => { state.logScope.reason = ""; }]);
  clear($("log-scope")).append(...chips.map(([, text, drop]) => h("span", { class: "scope-chip" }, text,
    h("button", { type: "button", class: "ghost", "aria-label": `Remove “${text}”`, onClick: () => { drop(); applyLogFilter(); } }, icon("x")))));
  $("log-scope").hidden = !chips.length;
}

// applyLogFilter records the Activity filter in the URL and loads it.
export function applyLogFilter() {
  setRoute("logs", "", logFilter());
  renderLogScope();
  if (state.live) startLive();
  else loadLogs(true).catch(report);
}

// CHECKS are the names, for people, of the policy checks that decisions'
// reasons and explanations' timelines give by ID.
export const CHECKS = {
  upstream: "Upstream", local: "Local name", rewrite: "Rewrite", allow: "Allowed domains", deny: "Denied domains",
  service: "Blocked apps", schedule: "Schedules", bypass: "Bypass protection", tld: "Blocked TLDs", list: "Blocklists",
  homograph: "Look-alike names", tunneling: "DNS tunneling", "newly-registered": "Newly registered domains",
  "safe-search": "Safe search", rebinding: "DNS rebinding", cname: "CNAME targets", resolved: "Resolved",
};

export const checkName = (id) => CHECKS[id] || id;

// reasonText says briefly why a query was decided as it was, naming the
// app or schedule that blocked it.
export function reasonText(e) {
  if (e.reason === "service" && e.source) return `App: ${serviceName(e.source)}`;
  if (e.reason === "schedule" && e.source) return `Schedule: ${e.source}`;
  if (e.reason === "list" && e.source) return `Blocklist: ${listTitle(e.source)}`;
  return e.reason ? checkName(e.reason) : "";
}

// STATUS_WORDS say each status in words, with a symbol, so it never
// rests on color.
export const STATUS_WORDS = { allowed: ["Allowed", "allow"], blocked: ["Blocked", "block"], rewritten: ["Rewritten", "arrow"], error: ["Failed", "warn"] };

export function statusPill(status) {
  const [word, sym] = STATUS_WORDS[status] || [status, "arrow"];
  return h("span", { class: `pill ${status}` }, icon(sym), word);
}

export function logRow(e) {
  // Hostnames are what devices call themselves, so they read as labels.
  const who = e.device || e.hostname || e.client || "—";
  const tr = h("tr", { tabindex: 0, "aria-label": `${e.name}, ${(STATUS_WORDS[e.status] || [e.status])[0]}, ${fmtTime(e.time)}` },
    h("td", { class: "c-time", title: fmtTime(e.time, true), text: fmtTime(e.time) }),
    h("td", { class: "c-who mono", title: e.client || "", text: who }),
    h("td", { class: "c-name name", text: e.name }),
    h("td", { class: "c-type", text: e.type }),
    h("td", { class: "c-status" }, statusPill(e.status), e.cached ? h("span", { class: "muted cached", text: "cached" }) : null),
    h("td", { class: "c-why", text: reasonText(e) }),
    h("td", { class: "c-ms num", text: (e.duration_ms ?? 0).toFixed(1) }),
  );
  const open = () => openDrawer(e);
  tr.addEventListener("click", open);
  tr.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); open(); } });
  return tr;
}

// loadLogs loads the first page of Activity, or with reset false, the
// next. Only the latest load shows, however responses arrive.
export let logSeq = 0;

export async function loadLogs(reset) {
  const seq = ++logSeq;
  const rows = $("log-rows");
  const filter = logFilter();
  const query = { ...filter, limit: 100 };
  if (!reset && state.logNext) query.page_token = state.logNext;
  const page = await api("GET", "/logs", { query });
  if (seq !== logSeq) return;
  if (reset) clear(rows);
  for (const e of page.entries || []) rows.append(logRow(e));
  state.logNext = page.next_page_token || "";
  $("load-more").hidden = !state.logNext;
  const empty = rows.childElementCount === 0;
  $("log-empty").hidden = !empty;
  $("log-table").hidden = empty;
  const narrowed = Object.values(filter).some(Boolean);
  $("log-empty-hint").textContent = narrowed ? "Try a wider filter." : "Queries appear here as devices use this server.";
}

export function stopLive() {
  if (state.live) state.live.abort();
  state.live = null;
  const box = $("live");
  if (box) box.checked = false;
}

export async function startLive() {
  stopLive();
  $("live").checked = true;
  const ctl = new AbortController();
  state.live = ctl;
  try {
    const resp = await api("GET", "/logs/stream", { query: logFilter(), signal: ctl.signal, raw: true });
    const reader = resp.body.pipeThrough(new TextDecoderStream()).getReader();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += value;
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const block = buf.slice(0, i);
        buf = buf.slice(i + 2);
        const data = block.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).replace(/^ /, "")).join("\n");
        if (!data) continue;
        let entry;
        try { entry = JSON.parse(data); } catch { continue; }
        const rows = $("log-rows");
        rows.prepend(logRow(entry));
        while (rows.childElementCount > LIVE_CAP) rows.lastElementChild.remove();
        $("log-empty").hidden = true;
        $("log-table").hidden = false;
      }
    }
    if (state.live === ctl) toast("Live stream ended.");
  } catch (err) {
    report(err);
  } finally {
    if (state.live === ctl) stopLive();
  }
}

export function openDrawer(e) {
  const body = clear($("drawer-body"));
  const kv = (k, v) => { if (v !== undefined && v !== "" && v !== null) body.append(h("dt", { text: k }), h("dd", {}, v)); };
  $("drawer-title").textContent = e.name;
  kv("Time", fmtTime(e.time, true));
  kv("Status", h("span", { class: `pill ${e.status}`, text: e.status + (e.cached ? " (cached)" : "") }));
  kv("Reason", e.reason && checkName(e.reason));
  if (e.reason === "service") kv("App", e.source && serviceName(e.source));
  else if (e.reason === "schedule") kv("Schedule", e.source && h("span", { title: "Blocked while this schedule is in effect.", text: e.source }));
  kv("Why", e.detail);
  kv("Rule", e.rule && h("span", { class: "mono", text: e.rule }));
  if (e.reason !== "service" && e.reason !== "schedule") kv("Source", e.source);
  kv("Type", e.type);
  kv("Rcode", e.rcode);
  kv("Profile", e.profile);
  kv("Device", e.device);
  kv("Hostname", e.hostname && h("span", { title: "What the device calls itself on your network, as your router reports it. Devices choose their own hostnames, so it never decides which profile applies.", text: e.hostname }));
  kv("Client", e.client && h("span", { class: "mono", text: e.client }));
  kv("Transport", e.transport);
  kv("Upstream", e.upstream && h("span", { class: "mono", text: e.upstream }));
  kv("Duration", `${(e.duration_ms ?? 0).toFixed(2)} ms`);
  if (e.answers?.length) kv("Answers", h("div", {}, e.answers.map((a) => h("div", { class: "mono", text: a }))));

  const actions = clear($("drawer-actions"));
  if (e.profile && state.profiles.some((p) => p.id === e.profile)) {
    const blocked = e.status === "blocked";
    const kind = blocked ? "allow" : "deny";
    actions.append(edit(h("button", {
      type: "button", class: blocked ? "primary" : "",
      text: `${blocked ? "Allow" : "Block"} in ${e.profile}`,
      onClick: () => domainAction(e.profile, kind, e.name).then(() => toast(`${blocked ? "Allowed" : "Blocked"} ${e.name} in ${e.profile}`)).catch(report),
    })));
  }
  actions.append(h("button", {
    type: "button", text: "Explain",
    onClick: () => {
      $("x-name").value = e.name;
      $("x-type").value = e.type || "A";
      $("x-profile").value = e.profile || "";
      $("x-client").value = e.client || "";
      go("explain");
      runExplain().catch(report);
    },
  }));
  $("drawer").hidden = false;
  $("drawer-close").focus();
}

export function closeDrawer() {
  $("drawer").hidden = true;
}

// ---------- explain ----------
