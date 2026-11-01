// doh admin UI. Plain ES module, no dependencies.
//
// Everything shown here can come from the network, and query names are
// chosen by whoever sends a query, so the DOM is only ever built with
// createElement and textContent: never from HTML strings.

const API = "/api/v1";
const TOKEN_KEY = "doh.token";
const LIVE_CAP = 500;

const state = {
  token: "",
  etag: "",
  status: null,
  catalog: { features: [], presets: [] },
  profiles: [],
  selected: "",
  view: "overview",
  readOnly: false,
  logNext: "",
  live: null, // AbortController of the live stream
};

// ---------- DOM helpers ----------

const $ = (id) => document.getElementById(id);

// h builds an element. attrs: class, text, on{Event} listeners, dataset
// via data-*, booleans set as properties; children are nodes or strings.
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "checked" || k === "disabled" || k === "value" || k === "selected") el[k] = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function clear(el) {
  el.replaceChildren();
  return el;
}

// edit marks a control as editing the policy, disabling it when read-only.
function edit(el) {
  el.classList.add("edit");
  if (state.readOnly) el.disabled = true;
  return el;
}

function toast(message, { error = false, details = [] } = {}) {
  const t = h("div", { class: "toast" + (error ? " error" : ""), role: error ? "alert" : "status" }, message);
  if (details.length) t.append(h("ul", {}, details.map((d) => h("li", { text: d }))));
  $("toasts").append(t);
  setTimeout(() => t.remove(), error ? 8000 : 3500);
}

const nf = new Intl.NumberFormat();
const fmtNum = (n) => nf.format(n ?? 0);

function fmtTime(s, withDate = false) {
  if (!s) return "—";
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return "—";
  return withDate ? d.toLocaleString() : d.toLocaleTimeString();
}

function fmtDuration(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const d = Math.floor(s / 86400), hr = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${hr}h`;
  if (hr) return `${hr}h ${m}m`;
  if (m) return `${m}m`;
  return `${s}s`;
}

// ---------- API ----------

class APIError extends Error {
  constructor(status, body) {
    super(body?.error || `HTTP ${status}`);
    this.status = status;
    this.details = body?.details || [];
  }
}

async function api(method, path, { body, patch = false, query, signal, raw = false } = {}) {
  const headers = { Authorization: `Bearer ${state.token}`, Accept: "application/json" };
  const init = { method, headers, signal, cache: "no-store" };
  if (body !== undefined) {
    headers["Content-Type"] = patch ? "application/merge-patch+json" : "application/json";
    init.body = JSON.stringify(body);
  }
  if (method !== "GET" && state.etag) headers["If-Match"] = state.etag;

  let url = API + path;
  if (query) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== "") q.set(k, v);
    const s = q.toString();
    if (s) url += "?" + s;
  }

  const resp = await fetch(url, init);
  const etag = resp.headers.get("ETag");
  if (etag) state.etag = etag;

  if (resp.status === 401) {
    showSignIn("That token was not accepted. It may have been rotated.");
    throw new APIError(401, { error: "unauthorized" });
  }
  if (raw && resp.ok) return resp;

  let data = null;
  if (resp.status !== 204) {
    const text = await resp.text();
    if (text) {
      try { data = JSON.parse(text); } catch { data = { error: text.trim() }; }
    }
  }
  if (!resp.ok) {
    if (resp.status === 403) toast("This is a read-only token: changes need an admin token.", { error: true });
    if (resp.status === 412) {
      await loadPolicy();
      toast("The policy changed elsewhere, so it was reloaded. Try again.", { error: true });
    }
    throw new APIError(resp.status, data);
  }
  return data;
}

// report shows an API failure, unless it was already shown.
function report(err) {
  if (err.name === "AbortError") return;
  if (err instanceof APIError && [401, 403, 412].includes(err.status)) return;
  toast(err.message, { error: true, details: err.details || [] });
}

// ---------- auth ----------

function initToken() {
  const m = location.hash.match(/(?:^#|&)token=([^&]+)/);
  if (m) {
    sessionStorage.setItem(TOKEN_KEY, decodeURIComponent(m[1]));
    history.replaceState(null, "", location.pathname + location.search);
  }
  state.token = sessionStorage.getItem(TOKEN_KEY) || "";
}

function showSignIn(message = "") {
  stopLive();
  $("app").hidden = true;
  $("signin").hidden = false;
  const err = $("signin-error");
  err.textContent = message;
  err.hidden = !message;
  $("signin-token").focus();
}

async function signIn(token) {
  state.token = token;
  sessionStorage.setItem(TOKEN_KEY, token);
  try {
    await boot();
  } catch (err) {
    if (!(err instanceof APIError && err.status === 401)) showSignIn(err.message);
  }
}

function signOut() {
  stopLive();
  sessionStorage.removeItem(TOKEN_KEY);
  state.token = "";
  $("signin-token").value = "";
  showSignIn();
}

// ---------- boot and navigation ----------

async function boot() {
  const [status, catalog] = await Promise.all([api("GET", "/status"), api("GET", "/catalog")]);
  state.status = status;
  state.catalog = catalog || { features: [], presets: [] };
  setReadOnly(status.policy);
  await loadPolicy();
  $("signin").hidden = true;
  $("app").hidden = false;
  show(state.view);
}

function setReadOnly(policy) {
  state.readOnly = !!policy?.read_only;
  const banner = $("readonly");
  banner.hidden = !state.readOnly;
  banner.textContent = state.readOnly
    ? policy.source
      ? `This policy is read-only: it is synced from ${policy.source}. Change it there.`
      : "This policy is read-only: it is built from the server's flags. Start the server with a policy file to edit it here."
    : "";
  for (const el of document.querySelectorAll(".edit")) el.disabled = state.readOnly;
}

async function loadPolicy() {
  const data = await api("GET", "/profiles");
  state.profiles = data?.profiles || [];
  if (!state.profiles.some((p) => p.id === state.selected)) state.selected = "";
  fillProfileSelects();
  if (state.view === "profiles") renderProfiles();
}

function show(view) {
  state.view = view;
  for (const b of document.querySelectorAll(".nav")) {
    if (b.dataset.view === view) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  }
  for (const v of ["overview", "profiles", "logs", "explain"]) $("view-" + v).hidden = v !== view;
  closeDrawer();
  if (view !== "logs") stopLive();
  const load = { overview: renderOverview, profiles: renderProfiles, logs: () => loadLogs(true), explain: () => {} }[view];
  Promise.resolve(load()).catch(report);
}

function fillProfileSelects() {
  for (const id of ["f-profile", "x-profile"]) {
    const sel = $(id);
    const keep = sel.value;
    const first = sel.options[0];
    sel.replaceChildren(first);
    for (const p of state.profiles) sel.append(h("option", { value: p.id, text: p.name ? `${p.name} (${p.id})` : p.id }));
    sel.value = state.profiles.some((p) => p.id === keep) ? keep : "";
  }
}

// ---------- overview ----------

async function renderOverview() {
  const [status, stats] = await Promise.all([api("GET", "/status"), api("GET", "/stats", { query: { top: 10 } })]);
  state.status = status;
  setReadOnly(status.policy);

  const total = stats.total || 0;
  const blocked = stats.by_status?.blocked || 0;
  const pct = total ? ((blocked / total) * 100).toFixed(1) + "%" : "—";
  const card = (label, value, sub) =>
    h("div", { class: "card stat" }, h("div", { class: "value", text: value }), h("div", { class: "label", text: label }), sub && h("div", { class: "label", text: sub }));
  clear($("stat-cards")).append(
    card("Queries", fmtNum(total), stats.since ? `since ${fmtTime(stats.since, true)}` : "in the log"),
    card("Blocked", fmtNum(blocked), pct),
    card("Rewritten", fmtNum(stats.by_status?.rewritten)),
    card("Errors", fmtNum(stats.by_status?.error)),
    card("Since start", fmtNum(status.queries?.total), `${fmtNum(status.queries?.cached)} from cache`),
  );

  const reasons = Object.entries(stats.by_reason || {}).sort((a, b) => b[1] - a[1]);
  const maxR = Math.max(1, ...reasons.map((r) => r[1]));
  const bars = clear($("by-reason"));
  if (!reasons.length) bars.append(h("p", { class: "muted", text: "Nothing blocked yet." }));
  for (const [reason, n] of reasons) {
    const fill = h("span");
    fill.style.width = `${(n / maxR) * 100}%`;
    bars.append(h("div", { class: "bar-row" }, h("span", { text: reason }), h("div", { class: "bar" }, fill), h("span", { class: "num", text: fmtNum(n) })));
  }

  const listing = (el, items) => {
    clear(el);
    if (!items?.length) el.append(h("li", { class: "muted", text: "None yet." }));
    for (const c of items || []) el.append(h("li", {}, h("span", { class: "count", text: fmtNum(c.count) }), h("span", { class: "mono", text: c.name })));
  };
  listing($("top-blocked"), stats.top_blocked);
  listing($("top-clients"), stats.top_clients);

  const info = clear($("server-info"));
  const kv = (k, v) => info.append(h("dt", { text: k }), h("dd", {}, v));
  kv("Version", status.version || "—");
  kv("Uptime", status.started ? fmtDuration(Date.now() - new Date(status.started)) : "—");
  for (const [k, v] of Object.entries(status.listeners || {})) kv(`Listener (${k})`, h("span", { class: "mono", text: v }));
  kv("Upstreams", h("span", { class: "mono", text: (status.upstreams || []).join(", ") || "—" }));
  kv("Policy", status.policy?.source || "flags");
  if (status.policy?.error) kv("Policy error", h("span", { class: "error", text: status.policy.error }));
  const ql = status.query_log || {};
  kv("Query log", ql.enabled ? `${fmtNum(ql.entries)} entries in memory${ql.dir ? `, kept ${ql.retention} on disk` : ""}` : "off");

  const rows = clear($("list-health"));
  if (!status.lists?.length) rows.append(h("tr", {}, h("td", { colspan: 4, class: "muted", text: "No blocklists in use." })));
  for (const l of status.lists || []) {
    const st = l.error ? h("span", { class: "pill blocked", title: l.error, text: "failed" }) : l.loading ? h("span", { class: "pill rewritten", text: "loading" }) : h("span", { class: "pill allowed", text: "ok" });
    rows.append(
      h("tr", {},
        h("td", {}, h("div", { text: l.name }), h("div", { class: "muted mono", text: l.location })),
        h("td", { class: "num", text: fmtNum(l.rules) }),
        h("td", { text: fmtTime(l.loaded, true) }),
        h("td", {}, st, l.error && h("div", { class: "muted", text: l.error })),
      ),
    );
  }
}

// ---------- profiles ----------

function renderProfiles() {
  const cards = clear($("profile-cards"));
  for (const p of state.profiles) {
    const devices = p.devices?.length || 0;
    const lists = p.lists?.length || 0;
    const on = Object.entries(p.security || {}).filter(([k, v]) => v === true).length;
    cards.append(
      h("button", { type: "button", class: "card", "aria-pressed": String(p.id === state.selected), onClick: () => selectProfile(p.id) },
        h("h3", { text: p.name || p.id }),
        h("div", { class: "profile-meta mono", text: p.id }),
        h("div", { class: "profile-meta", text: `${on} protections · ${lists} lists · ${devices} devices` }),
      ),
    );
  }
  if (!state.profiles.length) cards.append(h("p", { class: "muted", text: "No profiles: every client is refused. Create a profile named \"default\" to serve everyone else." }));
  renderEditor();
}

function selectProfile(id) {
  state.selected = state.selected === id ? "" : id;
  renderProfiles();
  if (state.selected) $("profile-editor").scrollIntoView({ behavior: "smooth", block: "start" });
}

function profile() {
  return state.profiles.find((p) => p.id === state.selected);
}

function replaceProfile(p) {
  const i = state.profiles.findIndex((x) => x.id === p.id);
  if (i >= 0) state.profiles[i] = p;
  else state.profiles.push(p);
}

// patchProfile applies a merge patch, re-rendering on success or failure.
async function patchProfile(id, patch) {
  try {
    const p = await api("PATCH", `/profiles/${encodeURIComponent(id)}`, { body: patch, patch: true });
    replaceProfile(p);
    return true;
  } catch (err) {
    report(err);
    return false;
  } finally {
    renderProfiles();
  }
}

async function domainAction(id, kind, domain, remove) {
  const path = `/profiles/${encodeURIComponent(id)}/${kind}` + (remove ? `/${encodeURIComponent(domain)}` : "");
  const p = await api(remove ? "DELETE" : "POST", path, remove ? {} : { body: { domain } });
  replaceProfile(p);
  return p;
}

function section(title, hint, ...body) {
  return h("div", { class: "section" }, h("h3", { text: title }), hint && h("p", { class: "muted hint", text: hint }), ...body);
}

// toggleRow renders a switch that applies a patch immediately.
function toggleRow(title, desc, checked, makePatch, extra) {
  const input = edit(h("input", { type: "checkbox", role: "switch", checked, "aria-label": title }));
  input.addEventListener("change", async () => {
    input.disabled = true;
    const ok = await patchProfile(state.selected, makePatch(input.checked));
    if (!ok) input.checked = !input.checked;
  });
  return h("div", { class: "toggle" },
    h("div", { class: "title", text: title }),
    h("div", { class: "control" }, extra, input),
    h("div", { class: "desc", text: desc }),
  );
}

// chipEditor edits a list of strings, calling add and remove.
function chipEditor(values, placeholder, label, add, remove) {
  const chips = h("div", { class: "chips" });
  for (const v of values || []) {
    chips.append(h("span", { class: "chip" }, v, edit(h("button", { type: "button", "aria-label": `Remove ${v}`, text: "✕", onClick: () => remove(v).catch(report) }))));
  }
  if (!values?.length) chips.append(h("span", { class: "muted", text: "None." }));
  const input = edit(h("input", { placeholder, "aria-label": label, spellcheck: "false" }));
  const form = h("form", { class: "chip-form" }, input, edit(h("button", { type: "submit", text: "Add" })));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const v = input.value.trim();
    if (v) add(v).then(() => toast(`Added ${v}`)).catch(report);
  });
  return h("div", {}, chips, form);
}

function renderEditor() {
  const box = $("profile-editor");
  const p = profile();
  box.hidden = !p;
  clear(box);
  if (!p) return;

  const id = p.id;
  const sec = p.security || {};
  const card = h("div", { class: "card" });
  box.append(card);

  const host = location.hostname || "doh.example.com";
  const url = `https://${host}/dns-query/${id}`;
  card.append(
    h("div", { class: "editor-head" },
      h("div", {}, h("h2", { text: p.name || p.id }), h("div", { class: "muted mono", text: id })),
      edit(h("button", { type: "button", class: "danger", text: "Delete profile", onClick: () => deleteProfile(p) })),
    ),
    h("div", { class: "doh-url" },
      h("span", { class: "muted", text: "DoH URL" }), h("code", { text: url }),
      h("button", { type: "button", class: "small", text: "Copy", onClick: () => navigator.clipboard?.writeText(url).then(() => toast("Copied"), () => toast("Couldn't copy", { error: true })) }),
    ),
    h("p", { class: "muted", text: `Devices can name themselves by appending /<device-name>, such as ${url}/living-room-tv. The ID is not a secret: anyone who knows it can use this profile.` }),
  );

  // Name
  const name = edit(h("input", { value: p.name || "", "aria-label": "Profile name" }));
  const nameForm = h("form", { class: "chip-form" }, name, edit(h("button", { type: "submit", text: "Rename" })));
  nameForm.addEventListener("submit", (e) => { e.preventDefault(); patchProfile(id, { name: name.value.trim() }); });
  card.append(section("Name", "", nameForm));

  // Security features
  const feats = state.catalog.features || [];
  const featToggle = (f) => {
    const isTop = f.id === "safe_search";
    const checked = isTop ? !!p.safe_search : !!sec[f.id];
    let extra;
    if (f.id === "newly_registered" && checked) {
      const days = edit(h("input", { type: "number", min: 1, max: 365, value: sec.newly_registered_days || 30, "aria-label": "Days" }));
      days.addEventListener("change", () => {
        const n = parseInt(days.value, 10);
        if (n >= 1 && n <= 365) patchProfile(id, { security: { newly_registered_days: n } });
      });
      extra = h("label", { class: "muted" }, "younger than ", days, " days");
    }
    return toggleRow(f.title, f.description, checked, (on) => (isTop ? { safe_search: on } : { security: { [f.id]: on } }), extra);
  };
  card.append(section("Security", "Built-in protections. Changes apply to new queries at once.",
    h("div", { class: "toggle-list" }, feats.filter((f) => f.category !== "parental").map(featToggle))));

  // Lists
  const lists = p.lists || [];
  const presets = state.catalog.presets || [];
  const presetNames = new Set(presets.map((x) => x.name));
  const listToggle = (pr) => toggleRow(pr.title, pr.description, lists.includes(pr.name), (on) => ({
    lists: on ? [...(profile().lists || []), pr.name] : (profile().lists || []).filter((l) => l !== pr.name),
  }));
  const group = (cat) => h("div", { class: "toggle-list" }, presets.filter((x) => x.category === cat).map(listToggle));
  const custom = lists.filter((l) => !presetNames.has(l) && l !== "default");
  card.append(
    section("Threat lists", "Blocklists of known-bad domains.", group("security")),
    section("Privacy", "Ads and trackers.", group("privacy")),
    section("Parental", "Content some households restrict.",
      h("div", { class: "toggle-list" }, feats.filter((f) => f.category === "parental").map(featToggle)), group("parental")),
    section("Custom lists", "Lists by URL or file path on the server, optionally named as name=location.",
      chipEditor(custom, "https://example.com/list.txt", "Custom list",
        (v) => patchProfile(id, { lists: [...lists, v] }),
        (v) => patchProfile(id, { lists: lists.filter((l) => l !== v) }))),
  );

  // Allow and deny
  const refresh = (pp) => { renderProfiles(); return pp; };
  card.append(
    section("Allowed domains", "Never blocked by anything in this profile, with their subdomains.",
      chipEditor(p.allow, "example.com", "Allow domain", (v) => domainAction(id, "allow", v).then(refresh), (v) => domainAction(id, "allow", v, true).then(refresh))),
    section("Denied domains", "Always blocked, with their subdomains.",
      chipEditor(p.deny, "example.com", "Deny domain", (v) => domainAction(id, "deny", v).then(refresh), (v) => domainAction(id, "deny", v, true).then(refresh))),
    section("Blocked TLDs", "Every name under these top-level domains.",
      chipEditor(p.block_tlds, "zip", "Block TLD",
        (v) => patchProfile(id, { block_tlds: [...(p.block_tlds || []), v.replace(/^\./, "")] }),
        (v) => patchProfile(id, { block_tlds: (p.block_tlds || []).filter((t) => t !== v) }))),
  );

  // Devices and clients
  const devices = p.devices || [];
  const devRows = h("div", { class: "rows" });
  for (const d of devices) {
    devRows.append(h("div", { class: "row-item" },
      h("strong", { text: d.name }), h("span", { class: "mono muted", text: (d.addrs || []).join(", ") || "DoH path only" }),
      edit(h("button", { type: "button", class: "small", text: "Remove", onClick: () => patchProfile(id, { devices: devices.filter((x) => x.name !== d.name) }) })),
    ));
  }
  if (!devices.length) devRows.append(h("span", { class: "muted", text: "No devices." }));
  const dName = edit(h("input", { placeholder: "living-room-tv", "aria-label": "Device name", spellcheck: "false" }));
  const dAddrs = edit(h("input", { placeholder: "192.168.1.50, fd00::50", "aria-label": "Device addresses", spellcheck: "false" }));
  const devForm = h("form", { class: "chip-form" }, dName, dAddrs, edit(h("button", { type: "submit", text: "Add device" })));
  devForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const n = dName.value.trim();
    if (!n) return;
    const addrs = dAddrs.value.split(/[\s,]+/).filter(Boolean);
    patchProfile(id, { devices: [...devices, { name: n, addrs }] });
  });
  card.append(
    section("Devices", "Named clients. Their addresses select this profile, and logs show their names.", devRows, devForm),
    section("Networks", "Addresses or prefixes whose queries use this profile. The most specific match wins.",
      chipEditor(p.clients, "192.168.1.0/24", "Client prefix",
        (v) => patchProfile(id, { clients: [...(p.clients || []), v] }),
        (v) => patchProfile(id, { clients: (p.clients || []).filter((c) => c !== v) }))),
  );

  // Rewrites
  const rewrites = p.rewrites || [];
  const rwRows = h("div", { class: "rows" });
  for (const rw of rewrites) {
    rwRows.append(h("div", { class: "row-item" },
      h("span", { class: "mono", text: rw.name }), h("span", { class: "muted", text: "→" }), h("span", { class: "mono", text: (rw.addrs || []).join(", ") }),
      edit(h("button", { type: "button", class: "small", text: "Remove", onClick: () => patchProfile(id, { rewrites: rewrites.filter((x) => x !== rw) }) })),
    ));
  }
  if (!rewrites.length) rwRows.append(h("span", { class: "muted", text: "No rewrites." }));
  const rName = edit(h("input", { placeholder: "nas.home.arpa", "aria-label": "Rewrite name", spellcheck: "false" }));
  const rAddrs = edit(h("input", { placeholder: "192.168.1.5", "aria-label": "Rewrite addresses", spellcheck: "false" }));
  const rwForm = h("form", { class: "chip-form" }, rName, rAddrs, edit(h("button", { type: "submit", text: "Add rewrite" })));
  rwForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const n = rName.value.trim();
    const addrs = rAddrs.value.split(/[\s,]+/).filter(Boolean);
    if (n && addrs.length) patchProfile(id, { rewrites: [...rewrites, { name: n, addrs }] });
  });
  card.append(section("Rewrites", "Answer names locally, such as a home server with its LAN address. Use *.domain for subdomains.", rwRows, rwForm));

  // Behavior
  const resp = edit(h("select", { "aria-label": "Block response" },
    h("option", { value: "nxdomain", text: "NXDOMAIN (name doesn't exist)" }),
    h("option", { value: "null", text: "Null address (0.0.0.0 and ::)" })));
  resp.value = p.block_response || "nxdomain";
  resp.addEventListener("change", () => patchProfile(id, { block_response: resp.value }));
  card.append(section("Behavior", "",
    h("div", { class: "toggle-list" },
      h("div", { class: "toggle" }, h("div", { class: "title", text: "Block response" }), h("div", { class: "control" }, resp), h("div", { class: "desc", text: "How blocked names are answered." })),
      toggleRow("Don't log this profile", "Keep its queries out of the query log. They're still counted in metrics.", !!p.logging?.disabled, (on) => ({ logging: { disabled: on } })),
    )));
}

function confirmDialog(title, text) {
  const dlg = $("confirm-dialog");
  $("confirm-title").textContent = title;
  $("confirm-text").textContent = text;
  return new Promise((resolve) => {
    dlg.addEventListener("close", () => resolve(dlg.returnValue === "ok"), { once: true });
    dlg.returnValue = "";
    dlg.showModal();
  });
}

async function deleteProfile(p) {
  const extra = p.id === "default" ? " Without a default profile, clients that match no other profile are refused." : "";
  if (!(await confirmDialog(`Delete ${p.name || p.id}?`, `Its devices will fall back to other profiles.${extra}`))) return;
  try {
    await api("DELETE", `/profiles/${encodeURIComponent(p.id)}`);
    state.profiles = state.profiles.filter((x) => x.id !== p.id);
    state.selected = "";
    fillProfileSelects();
    renderProfiles();
    toast(`Deleted ${p.id}`);
  } catch (err) {
    report(err);
  }
}

function openCreate() {
  $("c-id").value = "";
  $("c-name").value = "";
  $("create-dialog").showModal();
}

async function createProfile(e) {
  e.preventDefault();
  const id = $("c-id").value.trim();
  const name = $("c-name").value.trim();
  try {
    const p = await api("POST", "/profiles", { body: { id, name, security: {} } });
    $("create-dialog").close();
    replaceProfile(p);
    state.selected = p.id;
    fillProfileSelects();
    renderProfiles();
    toast(`Created ${p.id}`);
  } catch (err) {
    report(err);
  }
}

// ---------- query log ----------

function logFilter() {
  return {
    profile: $("f-profile").value,
    status: $("f-status").value,
    q: $("f-q").value.trim(),
    client: $("f-client").value.trim(),
  };
}

function logRow(e) {
  const who = e.device ? `${e.device}` : e.client || "—";
  const tr = h("tr", { tabindex: 0 },
    h("td", { title: fmtTime(e.time, true), text: fmtTime(e.time) }),
    h("td", { class: "mono", title: e.client || "", text: who }),
    h("td", { class: "name", text: e.name }),
    h("td", { text: e.type }),
    h("td", {}, h("span", { class: `pill ${e.status}`, text: e.status }), e.cached ? h("span", { class: "muted", text: " cached" }) : null),
    h("td", { text: e.reason || "" }),
    h("td", { class: "num", text: (e.duration_ms ?? 0).toFixed(1) }),
  );
  const open = () => openDrawer(e);
  tr.addEventListener("click", open);
  tr.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); open(); } });
  return tr;
}

async function loadLogs(reset) {
  const rows = $("log-rows");
  const query = { ...logFilter(), limit: 100 };
  if (!reset && state.logNext) query.page_token = state.logNext;
  const page = await api("GET", "/logs", { query });
  if (reset) clear(rows);
  for (const e of page.entries || []) rows.append(logRow(e));
  state.logNext = page.next_page_token || "";
  $("load-more").hidden = !state.logNext;
  $("log-empty").hidden = rows.childElementCount > 0;
}

function stopLive() {
  if (state.live) state.live.abort();
  state.live = null;
  const box = $("live");
  if (box) box.checked = false;
}

async function startLive() {
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
      }
    }
    if (state.live === ctl) toast("Live stream ended.");
  } catch (err) {
    report(err);
  } finally {
    if (state.live === ctl) stopLive();
  }
}

function openDrawer(e) {
  const body = clear($("drawer-body"));
  const kv = (k, v) => { if (v !== undefined && v !== "" && v !== null) body.append(h("dt", { text: k }), h("dd", {}, v)); };
  $("drawer-title").textContent = e.name;
  kv("Time", fmtTime(e.time, true));
  kv("Status", h("span", { class: `pill ${e.status}`, text: e.status + (e.cached ? " (cached)" : "") }));
  kv("Reason", e.reason);
  kv("Rule", e.rule && h("span", { class: "mono", text: e.rule }));
  kv("Source", e.source);
  kv("Type", e.type);
  kv("Rcode", e.rcode);
  kv("Profile", e.profile);
  kv("Device", e.device);
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
      show("explain");
      runExplain().catch(report);
    },
  }));
  $("drawer").hidden = false;
  $("drawer-close").focus();
}

function closeDrawer() {
  $("drawer").hidden = true;
}

// ---------- explain ----------

async function runExplain(ev) {
  ev?.preventDefault();
  const out = clear($("explain-result"));
  const x = await api("GET", "/explain", {
    query: { name: $("x-name").value.trim(), type: $("x-type").value.trim() || "A", profile: $("x-profile").value, client: $("x-client").value.trim() },
  });
  const d = x.decision || {};
  const card = h("div", { class: "card" });
  card.append(
    h("div", { class: "decision" },
      h("span", { class: `pill ${d.action}`, text: d.action }),
      h("strong", { class: "mono", text: `${x.name} ${x.type}` }),
      x.rcode && h("span", { class: "muted", text: x.rcode }),
    ),
    d.detail && h("p", { text: d.detail }),
  );
  const facts = h("dl", { class: "kv" });
  const kv = (k, v) => { if (v) facts.append(h("dt", { text: k }), h("dd", { class: "mono", text: v })); };
  kv("Profile", x.profile);
  kv("Device", x.device);
  kv("Client", x.client);
  kv("Reason", d.reason);
  kv("Rule", d.rule);
  kv("Source", d.source);
  card.append(facts);
  card.append(h("ol", { class: "timeline", "aria-label": "Checks" },
    (x.checks || []).map((c) => h("li", { class: c.result },
      h("span", { class: "check", text: c.check }),
      h("span", { class: `pill ${c.result}`, text: c.result }),
      c.detail && h("div", { class: "muted", text: c.detail }),
    ))));
  if (x.answers?.length) card.append(h("div", { class: "section" }, h("h3", { text: "Answers" }), x.answers.map((a) => h("div", { class: "mono", text: a }))));
  if (x.profile && state.profiles.some((p) => p.id === x.profile)) {
    const blocked = d.action === "block";
    card.append(h("div", { class: "actions" }, edit(h("button", {
      type: "button", class: blocked ? "primary" : "",
      text: `${blocked ? "Allow" : "Block"} ${x.name} in ${x.profile}`,
      onClick: () => domainAction(x.profile, blocked ? "allow" : "deny", x.name).then(() => { toast("Done"); return runExplain(); }).catch(report),
    }))));
  }
  out.append(card);
}

// ---------- wiring ----------

function wire() {
  $("signin-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const t = $("signin-token").value.trim();
    if (t) signIn(t);
  });
  $("signout").addEventListener("click", signOut);
  for (const b of document.querySelectorAll(".nav")) b.addEventListener("click", () => show(b.dataset.view));
  $("new-profile").addEventListener("click", openCreate);
  $("create-form").addEventListener("submit", createProfile);
  $("create-cancel").addEventListener("click", () => $("create-dialog").close());
  $("log-filters").addEventListener("submit", (e) => {
    e.preventDefault();
    if (state.live) startLive();
    else loadLogs(true).catch(report);
  });
  $("load-more").addEventListener("click", () => loadLogs(false).catch(report));
  $("live").addEventListener("change", (e) => {
    if (e.target.checked) { clear($("log-rows")); $("load-more").hidden = true; startLive(); }
    else { stopLive(); loadLogs(true).catch(report); }
  });
  $("explain-form").addEventListener("submit", (e) => runExplain(e).catch(report));
  $("drawer-close").addEventListener("click", closeDrawer);
  // Opening a sign-in link in a tab that already has the page loaded only
  // changes the hash.
  window.addEventListener("hashchange", () => {
    if (!/token=/.test(location.hash)) return;
    initToken();
    if (state.token) signIn(state.token);
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("drawer").hidden) closeDrawer(); });
}

wire();
initToken();
if (state.token) signIn(state.token);
else showSignIn();
