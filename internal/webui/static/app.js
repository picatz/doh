// doh admin UI. Plain ES module, no dependencies.
//
// Everything shown here can come from the network, and query names are
// chosen by whoever sends a query, so the DOM is only ever built with
// createElement and textContent: never from HTML strings.

const API = "/api/v1";
const AUTH = "/auth";
const LIVE_CAP = 500;

// The UI never holds an API token: the server signs the browser in with an
// HttpOnly session cookie, which fetch sends to this origin by itself.
const state = {
  auth: null, // the server's SessionStatus
  etag: "",
  status: null,
  catalog: { features: [], presets: [] },
  profiles: [],
  tenants: [], // every tenant for the operator, or the caller's own
  selected: "",
  view: "overview",
  readOnly: false,
  logNext: "",
  live: null, // AbortController of the live stream
  connect: { device: "", platform: "" }, // the "Connect a device" choices
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
  const headers = { Accept: "application/json" };
  const init = { method, headers, signal, cache: "no-store", credentials: "same-origin" };
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
    showSignIn("Your session ended. Sign in again.");
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
    if (resp.status === 403) toast(isAdmin() && data?.error ? data.error : "You're signed in read-only: changes need an admin.", { error: true });
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

// ---------- sign-in ----------

// authCall calls a sign-in endpoint, returning its JSON, or throwing an
// APIError with the server's message.
async function authCall(method, path, body) {
  const init = { method, headers: { Accept: "application/json" }, cache: "no-store", credentials: "same-origin" };
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = typeof body === "string" ? body : JSON.stringify(body);
  }
  const resp = await fetch(AUTH + path, init);
  const text = resp.status === 204 ? "" : await resp.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text.trim() }; }
  }
  if (!resp.ok) throw new APIError(resp.status, data);
  return data;
}

// takeLinkCode removes a sign-in link's code from the address bar, so it
// isn't left in history or shared by accident, and returns it.
function takeLinkCode() {
  const m = location.hash.match(/(?:^#|&)signin=([A-Za-z0-9_-]+)/);
  if (!m) return "";
  history.replaceState(null, "", location.pathname + location.search);
  return m[1];
}

// start signs in with a link in the address bar, if there is one, and
// shows the app or the sign-in screen.
async function start() {
  const code = takeLinkCode();
  try {
    let status = await authCall("GET", "/session");
    if (code) {
      try {
        status = await authCall("POST", "/link", { code });
      } catch (err) {
        state.auth = status;
        if (err instanceof APIError && err.status === 401) {
          showSignIn("That sign-in link is invalid, used, or expired. Run doh ui on the server for a new one.");
          return;
        }
        throw err;
      }
    }
    await route(status);
  } catch (err) {
    showSignIn(err.message);
  }
}

// route shows what a session status calls for: the app, the second step
// of a link sign-in, or the sign-in screen.
async function route(status) {
  state.auth = status;
  if (status.signed_in) {
    await enterApp();
  } else if (status.session?.pending && status.session.method === "link") {
    showSignIn("", { pending: true });
  } else {
    showSignIn();
  }
}

function showSignIn(message = "", { pending = false } = {}) {
  stopLive();
  closeDrawer();
  $("app").hidden = true;
  $("signin").hidden = false;

  $("signin-title").textContent = pending ? "Finish signing in" : "Sign in to doh";
  $("signin-lede").textContent = pending
    ? "Your sign-in link worked. This server uses passkeys, so finish with yours."
    : "Use the passkey you added to this server: Face ID, Touch ID, Windows Hello, or a security key.";
  $("signin-passkey").textContent = pending ? "Continue with a passkey" : "Sign in with a passkey";
  $("signin-link-hint").hidden = pending;

  const host = $("signin-host");
  const rpID = state.auth?.rp_id;
  host.hidden = !rpID || location.hostname === rpID;
  if (!host.hidden) {
    const there = new URL(location.href);
    there.hostname = rpID;
    there.hash = "";
    clear(host).append("Passkeys for this server only work at ", h("a", { href: there.href, text: there.host }), ".");
  }

  const err = $("signin-error");
  err.textContent = message;
  err.hidden = !message;
  $("signin-passkey").focus();
}

// signInWithPasskey runs a passkey sign-in: alone, or to finish a link.
async function signInWithPasskey() {
  const button = $("signin-passkey");
  button.disabled = true;
  try {
    const begin = await authCall("POST", "/passkey/login", {});
    const credential = await navigator.credentials.get({ publicKey: webauthnJSON.requestOptions(begin.options.publicKey) });
    const status = await authCall("POST", `/passkey/login/${encodeURIComponent(begin.id)}`, JSON.stringify(webauthnJSON.credential(credential)));
    await route(status);
  } catch (err) {
    showSignIn(passkeyError(err), { pending: !!state.auth?.session?.pending && state.auth.session.method === "link" });
  } finally {
    button.disabled = false;
  }
}

// passkeyError explains why a passkey ceremony failed.
function passkeyError(err) {
  switch (err?.name) {
    case "NotAllowedError": return "The passkey request was cancelled or timed out.";
    case "InvalidStateError": return "This authenticator already has a passkey for this server.";
    case "SecurityError": return `Passkeys only work at ${state.auth?.rp_id || "this server's host name"}.`;
    case "NotSupportedError": return "This browser or device doesn't support passkeys.";
    default: return err?.message || "Something went wrong.";
  }
}

async function signOut() {
  stopLive();
  try {
    await authCall("POST", "/signout");
  } catch (err) {
    report(err);
  }
  state.auth = await authCall("GET", "/session").catch(() => state.auth);
  showSignIn();
}

// refreshAuth reloads the session status, such as after adding a passkey
// turns a link session into a person's.
async function refreshAuth() {
  state.auth = await authCall("GET", "/session");
  renderWho();
}

// renderWho shows who's signed in, and recommends a passkey after a link
// sign-in while no one has one.
function renderWho() {
  const s = state.auth?.session;
  const tenant = state.status?.tenant;
  // Node.append would turn a missing badge into the text "null", so filter.
  clear($("who")).append(...[
    tenant && h("span", { class: "badge tenant", title: "Your tenant", text: tenantName(tenant) }),
    h("span", { class: "who-name", text: s?.name || "" }),
    s?.role && h("span", { class: "badge", text: s.role }),
  ].filter(Boolean));
  $("passkey-banner").hidden = !(s && !s.person && !state.auth.passkeys_required);
}

const isAdmin = () => state.auth?.session?.role === "admin";

// isOperator reports whether the UI acts as the server's operator, rather
// than for a tenant: the server tells tenants which one they are.
const isOperator = () => !state.status?.tenant;

const tenantOf = (id) => state.tenants.find((t) => t.id === id);
const tenantName = (id) => tenantOf(id)?.name || id;

// ---------- passkeys ----------

// webauthnJSON converts between the WebAuthn JSON forms the server speaks
// and the objects navigator.credentials uses: natively where the browser
// can, and otherwise by decoding and encoding the base64url fields
// (WebAuthn Level 3, sections 5.1.8 and 5.1.9).
const webauthnJSON = (() => {
  const toBytes = (s) => {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  };
  const toB64URL = (buf) => {
    if (!buf) return null;
    let s = "";
    for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const descriptors = (list) => list?.map((d) => ({ ...d, id: toBytes(d.id) }));
  const PKC = window.PublicKeyCredential;

  return {
    creationOptions(json) {
      if (PKC?.parseCreationOptionsFromJSON) return PKC.parseCreationOptionsFromJSON(json);
      return { ...json, challenge: toBytes(json.challenge), user: { ...json.user, id: toBytes(json.user.id) }, excludeCredentials: descriptors(json.excludeCredentials) };
    },
    requestOptions(json) {
      if (PKC?.parseRequestOptionsFromJSON) return PKC.parseRequestOptionsFromJSON(json);
      return { ...json, challenge: toBytes(json.challenge), allowCredentials: descriptors(json.allowCredentials) };
    },
    credential(cred) {
      if (typeof cred.toJSON === "function") return cred.toJSON();
      const r = cred.response;
      const response = { clientDataJSON: toB64URL(r.clientDataJSON) };
      if (r.attestationObject) {
        response.attestationObject = toB64URL(r.attestationObject);
        if (r.getAuthenticatorData) response.authenticatorData = toB64URL(r.getAuthenticatorData());
        if (r.getTransports) response.transports = r.getTransports();
        if (r.getPublicKeyAlgorithm) response.publicKeyAlgorithm = r.getPublicKeyAlgorithm();
      } else {
        response.authenticatorData = toB64URL(r.authenticatorData);
        response.signature = toB64URL(r.signature);
        response.userHandle = toB64URL(r.userHandle);
      }
      return {
        id: cred.id, rawId: toB64URL(cred.rawId), type: cred.type,
        authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
        clientExtensionResults: cred.getClientExtensionResults(),
        response,
      };
    },
  };
})();

// ---------- boot and navigation ----------

async function enterApp() {
  const [status, catalog] = await Promise.all([api("GET", "/status"), api("GET", "/catalog")]);
  state.status = status;
  state.catalog = catalog || { features: [], presets: [] };
  setReadOnly(status.policy);
  await Promise.all([loadPolicy(), loadTenants()]);
  // Only the operator manages tenants and sees how the server runs.
  $("nav-tenants").hidden = !isOperator();
  $("list-health-card").hidden = !isOperator();
  renderWho();
  $("signin").hidden = true;
  $("app").hidden = false;
  show(state.view);
}

function setReadOnly(policy) {
  const reader = !isAdmin();
  state.readOnly = !!policy?.read_only || reader;
  const banner = $("readonly");
  banner.hidden = !state.readOnly;
  banner.textContent = !state.readOnly ? ""
    : reader ? "You're signed in read-only. Changes need an admin."
    : policy.source ? `This policy is read-only: it is synced from ${policy.source}. Change it there.`
    : "This policy is read-only: it is built from the server's flags. Start the server with a policy file to edit it here.";
  for (const el of document.querySelectorAll(".edit")) el.disabled = state.readOnly;
}

// loadTenants loads the tenants the caller can see.
async function loadTenants() {
  const data = await api("GET", "/tenants");
  state.tenants = data?.tenants || [];
}

async function loadPolicy() {
  const data = await api("GET", "/profiles");
  state.profiles = data?.profiles || [];
  if (!state.profiles.some((p) => p.id === state.selected)) state.selected = "";
  fillProfileSelects();
  if (state.view === "profiles") renderProfiles();
}

function show(view) {
  if (view === "tenants" && !isOperator()) view = "overview";
  state.view = view;
  for (const b of document.querySelectorAll(".nav")) {
    if (b.dataset.view === view) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  }
  for (const v of ["overview", "profiles", "logs", "explain", "security", "tenants"]) $("view-" + v).hidden = v !== view;
  closeDrawer();
  if (view !== "logs") stopLive();
  const load = { overview: renderOverview, profiles: renderProfiles, logs: () => loadLogs(true), explain: () => {}, security: renderSecurity, tenants: renderTenants }[view];
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
    status.queries && card("Since start", fmtNum(status.queries.total), `${fmtNum(status.queries.cached)} from cache`),
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
  if (!isOperator()) {
    // Tenants see their own corner of the server.
    $("server-title").textContent = "Your tenant";
    kv("Tenant", tenantName(status.tenant));
    kv("Profiles", fmtNum(status.policy?.profiles));
    kv("Query log", status.query_log?.enabled ? "on" : "off");
    kv("Version", status.version || "—");
    return;
  }
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
        isOperator() && p.tenant ? h("span", { class: "badge tenant", text: tenantName(p.tenant) }) : null,
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

// ---------- connecting devices ----------

// DEVICE_NAME matches device names: DNS labels of lower-case letters,
// digits, and single hyphens, as the server requires.
const DEVICE_NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

const validDevice = (name) => name === "" || (DEVICE_NAME.test(name) && !name.includes("--"));

// guessPlatform picks the platform of the browser showing the UI, which is
// often the device being set up.
function guessPlatform() {
  const ua = navigator.userAgent;
  if (/iPhone|iPad|Macintosh/.test(ua)) return "apple";
  if (/Android/.test(ua)) return "android";
  if (/Windows/.test(ua)) return "windows";
  if (/Linux/.test(ua)) return "linux";
  return "";
}

// copyButton copies text to the clipboard.
function copyButton(text, label) {
  return h("button", {
    type: "button", class: "small", text: "Copy", "aria-label": `Copy ${label}`,
    onClick: () => navigator.clipboard?.writeText(text).then(() => toast(`Copied ${label}`), () => toast("Couldn't copy", { error: true })),
  });
}

// connectSection shows how to point a device at profile p: the encrypted
// DNS endpoints that select it, and instructions per platform, from the
// server's setup endpoint. Reading it needs no admin token.
function connectSection(p) {
  const id = p.id;
  const body = h("div", { class: "connect", "aria-live": "polite" }, h("p", { class: "muted", text: "Loading…" }));

  const device = h("input", {
    value: state.connect.device, placeholder: "living-room-tv", "aria-label": "Device name",
    spellcheck: "false", autocomplete: "off", autocapitalize: "none", maxlength: 63,
  });
  const deviceError = h("span", { class: "field-error", role: "alert" });
  const deviceRow = h("label", { class: "device-name" },
    h("span", { text: "Device name" }),
    device,
    h("span", { class: "muted hint", text: "Optional: lower-case letters, digits, and hyphens. Logs show it." }),
    deviceError,
  );

  let request = 0;
  const load = async () => {
    const name = device.value.trim().toLowerCase();
    const ok = validDevice(name);
    device.setAttribute("aria-invalid", String(!ok));
    deviceError.textContent = ok ? "" : "Use lower-case letters, digits, and single hyphens, starting and ending with a letter or digit.";
    if (!ok) return;
    state.connect.device = name;

    const mine = ++request;
    try {
      const setup = await api("GET", `/profiles/${encodeURIComponent(id)}/setup`, { query: { device: name } });
      if (mine === request) renderSetup(body, setup);
    } catch (err) {
      if (mine === request) clear(body).append(h("p", { class: "error", text: err.message }));
    }
  };

  let timer;
  device.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(load, 250);
  });
  load();

  return section("Connect a device",
    "Point a phone, tablet, or computer at this profile. The profile ID isn't a secret: anyone who knows it can use this profile.",
    deviceRow, body);
}

// renderSetup fills body with a setup's endpoints and instructions.
function renderSetup(body, setup) {
  clear(body);

  const endpoints = [
    ["DNS-over-HTTPS", setup.doh_url],
    ["DNS-over-TLS", setup.dot_host],
    ["Plain DNS", (setup.dns_addrs || []).join(", ")],
  ].filter(([, v]) => v);
  if (endpoints.length) {
    body.append(h("dl", { class: "endpoints" }, endpoints.flatMap(([label, value]) => [
      h("dt", { text: label }),
      h("dd", {}, h("code", { text: value }), copyButton(value, label)),
    ])));
  }

  const platforms = setup.platforms || [];
  if (!platforms.length) return;

  const ids = platforms.map((pl) => pl.id);
  let current = ids.includes(state.connect.platform) ? state.connect.platform
    : ids.includes(guessPlatform()) ? guessPlatform() : ids[0];

  const tabs = h("div", { class: "segmented", role: "tablist", "aria-label": "Platform" });
  const panel = h("div", { class: "platform", role: "tabpanel" });

  const select = (platformID, focus = false) => {
    current = platformID;
    state.connect.platform = platformID;
    for (const tab of tabs.children) {
      const on = tab.dataset.platform === platformID;
      tab.setAttribute("aria-selected", String(on));
      tab.tabIndex = on ? 0 : -1;
      if (on && focus) tab.focus();
    }
    const pl = platforms.find((x) => x.id === platformID);
    panel.setAttribute("aria-label", pl.name);
    clear(panel).append(h("ol", { class: "steps" }, pl.steps.map((step) => h("li", { text: step }))));
    if (pl.id === "apple" && pl.download) panel.append(appleDownloads(setup));
  };

  for (const pl of platforms) {
    tabs.append(h("button", {
      type: "button", role: "tab", text: pl.name, "data-platform": pl.id,
      onClick: () => select(pl.id),
    }));
  }
  // Arrow keys move between tabs, as WAI-ARIA's tabs pattern describes.
  tabs.addEventListener("keydown", (e) => {
    const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
    if (!step) return;
    e.preventDefault();
    const i = ids.indexOf(current);
    select(ids[(i + step + ids.length) % ids.length], true);
  });

  body.append(tabs, panel);
  select(current);
}

// appleDownloads offers configuration profiles for Apple devices.
function appleDownloads(setup) {
  const buttons = h("div", { class: "downloads" });
  const offer = (label, protocol, primary) => buttons.append(h("button", {
    type: "button", class: primary ? "primary" : "", text: label,
    onClick: (e) => downloadMobileConfig(setup, protocol, e.currentTarget),
  }));
  if (setup.doh_url) offer("Download configuration profile", "https", true);
  if (setup.dot_host) offer(setup.doh_url ? "DNS-over-TLS version" : "Download configuration profile", "tls", !setup.doh_url);
  buttons.append(h("p", { class: "muted hint", text: "Configuration profiles aren't signed, so devices show them as unverified. Downloading again replaces the installed one." }));
  return buttons;
}

// downloadMobileConfig fetches a configuration profile, so a failure can be
// shown here rather than saved as a file, and saves it through a temporary
// object URL.
async function downloadMobileConfig(setup, protocol, button) {
  button.disabled = true;
  try {
    const resp = await api("GET", `/profiles/${encodeURIComponent(setup.profile)}/apple.mobileconfig`, {
      query: { device: setup.device, protocol }, raw: true,
    });
    const blob = await resp.blob();
    const name = [setup.profile, setup.device].filter(Boolean).join("-") + ".mobileconfig";

    const url = URL.createObjectURL(blob);
    const a = h("a", { href: url, download: name, hidden: true });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    toast(`Downloaded ${name}`);
  } catch (err) {
    report(err);
  } finally {
    button.disabled = false;
  }
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

  card.append(
    h("div", { class: "editor-head" },
      h("div", {},
        h("h2", { text: p.name || p.id }),
        h("div", { class: "muted mono", text: id }),
        isOperator() && p.tenant ? h("span", { class: "badge tenant", text: `Tenant: ${tenantName(p.tenant)}` }) : null,
      ),
      edit(h("button", { type: "button", class: "danger", text: "Delete profile", onClick: () => deleteProfile(p) })),
    ),
    connectSection(p),
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
    customListsSection(p, custom, lists),
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
  const bounds = networkHint(p);
  card.append(
    section("Devices", "Named clients. Their addresses select this profile, and logs show their names.", bounds, devRows, devForm),
    section("Networks", "Addresses or prefixes whose queries use this profile. The most specific match wins.", bounds?.cloneNode(true),
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

// customListsSection edits a profile's lists by URL or path. A tenant's
// profiles may only use presets, unless the operator allows HTTPS lists,
// since the server downloads them.
function customListsSection(p, custom, lists) {
  const id = p.id;
  const editor = (placeholder) => chipEditor(custom, placeholder, "Custom list",
    (v) => patchProfile(id, { lists: [...lists, v] }),
    (v) => patchProfile(id, { lists: lists.filter((l) => l !== v) }));

  if (!p.tenant) {
    return section("Custom lists", "Lists by URL or file path on the server, optionally named as name=location.", editor("https://example.com/list.txt"));
  }
  if (tenantOf(p.tenant)?.custom_lists) {
    return section("Custom lists", "Lists by HTTPS URL, optionally named as name=URL.", editor("https://example.com/list.txt"));
  }
  return section("Custom lists", "",
    h("p", { class: "muted", text: "This profile's tenant can use preset lists only. Ask the server's operator to allow custom lists." }),
    custom.length ? h("div", { class: "chips" }, custom.map((v) => h("span", { class: "chip", text: v }))) : null);
}

// networkHint says which addresses a tenant's profile may select devices
// by: only those within its tenant's networks.
function networkHint(p) {
  if (!p.tenant) return null;
  const nets = tenantOf(p.tenant)?.networks || [];
  return h("p", { class: "field-note" }, nets.length
    ? `Addresses must be within this tenant's networks: ${nets.join(", ")}.`
    : "This tenant has no networks, so its devices select profiles by DoH path or host name.");
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
  const sel = $("c-tenant");
  sel.replaceChildren(sel.options[0]);
  for (const t of state.tenants) sel.append(h("option", { value: t.id, text: t.name ? `${t.name} (${t.id})` : t.id }));
  sel.value = "";
  // Tenants' profiles are always their own; only the operator chooses.
  $("c-tenant-row").hidden = !isOperator() || !state.tenants.length;
  $("create-dialog").showModal();
}

async function createProfile(e) {
  e.preventDefault();
  const id = $("c-id").value.trim();
  const name = $("c-name").value.trim();
  try {
    const tenant = isOperator() ? $("c-tenant").value : "";
    const p = await api("POST", "/profiles", { body: { id, name, tenant: tenant || undefined, security: {} } });
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
  // Hostnames are what devices call themselves, so they read as labels.
  const who = e.device || e.hostname || e.client || "—";
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

// ---------- tenants ----------

// renderTenants lists tenants for the operator, each editable in place.
async function renderTenants() {
  await Promise.all([loadTenants(), loadPolicy()]);
  const box = clear($("tenant-cards"));
  if (!state.tenants.length) {
    box.append(h("p", { class: "muted", text: "No tenants yet. Create one to share this server with another household." }));
    return;
  }
  for (const t of state.tenants) box.append(tenantCard(t));
}

// patchTenant applies a merge patch to a tenant, re-rendering the view.
async function patchTenant(id, patch) {
  const t = await api("PATCH", `/tenants/${encodeURIComponent(id)}`, { body: patch, patch: true });
  const i = state.tenants.findIndex((x) => x.id === id);
  if (i >= 0) state.tenants[i] = t;
  await renderTenants();
  return t;
}

function tenantCard(t) {
  const profiles = state.profiles.filter((p) => p.tenant === t.id);
  const networks = t.networks || [];

  const custom = edit(h("input", { type: "checkbox", role: "switch", checked: !!t.custom_lists, "aria-label": `Custom lists for ${t.id}` }));
  custom.addEventListener("change", () => patchTenant(t.id, { custom_lists: custom.checked }).catch((err) => { custom.checked = !custom.checked; report(err); }));

  const max = edit(h("input", { type: "number", min: 1, max: 1000, value: t.max_profiles || 20, "aria-label": `Most profiles for ${t.id}` }));
  max.addEventListener("change", () => {
    const n = parseInt(max.value, 10);
    if (n >= 1) patchTenant(t.id, { max_profiles: n }).catch(report);
  });

  const head = h("div", { class: "tenant-head" },
    h("h3", { text: t.name || t.id }),
    h("span", { class: "muted mono", text: t.id }),
    h("span", { class: "spacer" }),
    edit(h("button", { type: "button", class: "ghost danger-text", text: "Delete", onClick: () => deleteTenant(t, profiles.length) })),
  );

  return h("article", { class: "card tenant-card" },
    head,
    h("div", { class: "tenant-grid" },
      section("Networks", "Addresses its profiles may select devices by.",
        chipEditor(networks, "192.168.10.0/24", `Network for ${t.id}`,
          (v) => patchTenant(t.id, { networks: [...networks, v] }),
          (v) => patchTenant(t.id, { networks: networks.filter((n) => n !== v) }))),
      section("Profiles", "",
        profiles.length
          ? h("div", { class: "chips" }, profiles.map((p) => h("span", { class: "chip", text: p.id })))
          : h("p", { class: "muted", text: "None yet. Its admins create them, or you can from Profiles." })),
      section("Limits", "",
        h("div", { class: "toggle-list" },
          h("div", { class: "toggle" }, h("div", { class: "title", text: "Custom lists" }), h("div", { class: "control" }, custom),
            h("div", { class: "desc", text: "Let its profiles use blocklists by HTTPS URL, which this server downloads, not only presets." })),
          h("div", { class: "toggle" }, h("div", { class: "title", text: "Most profiles" }), h("div", { class: "control" }, max),
            h("div", { class: "desc", text: `It has ${profiles.length}.` })),
        )),
    ),
    inviteSection(t),
  );
}

// inviteSection makes single-use sign-in links for a tenant's people.
function inviteSection(t) {
  const result = h("div", { "aria-live": "polite" });
  const role = edit(h("select", { "aria-label": "Role" },
    h("option", { value: "admin", text: "Admin" }),
    h("option", { value: "reader", text: "Read-only" })));
  const button = edit(h("button", { type: "button", class: "primary", text: "Invite someone" }));
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      const link = await api("POST", "/signin-links", { body: { tenant: t.id, role: role.value } });
      clear(result).append(h("div", { class: "invite" },
        h("div", { class: "link" }, h("output", { text: link.url }), copyButton(link.url, "sign-in link")),
        h("p", { class: "field-note", text: `Send this to them. It works once, and expires at ${fmtTime(link.expires)}.${link.passkey_required ? " They'll finish with their passkey." : " They can add a passkey once signed in."}` }),
      ));
    } catch (err) {
      report(err);
    } finally {
      button.disabled = state.readOnly;
    }
  });
  return section("Invite", "A single-use sign-in link to this tenant, for its first admin or anyone else.",
    h("div", { class: "invite-form" }, role, button), result);
}

async function deleteTenant(t, profiles) {
  const text = profiles
    ? `It still has ${profiles} profile${profiles === 1 ? "" : "s"}: delete or move them first.`
    : "Its people and their passkeys are removed too, and they're signed out.";
  if (!(await confirmDialog(`Delete ${t.name || t.id}?`, text))) return;
  try {
    await api("DELETE", `/tenants/${encodeURIComponent(t.id)}`);
    toast(`Deleted ${t.id}`);
    await renderTenants();
  } catch (err) {
    report(err);
  }
}

function openCreateTenant() {
  for (const id of ["t-id", "t-name", "t-networks"]) $(id).value = "";
  $("tenant-dialog").showModal();
}

async function createTenant(e) {
  e.preventDefault();
  const body = {
    id: $("t-id").value.trim(),
    name: $("t-name").value.trim() || undefined,
    networks: $("t-networks").value.split(/[\s,]+/).filter(Boolean),
  };
  try {
    const t = await api("POST", "/tenants", { body });
    $("tenant-dialog").close();
    toast(`Created ${t.id}. Invite its first admin below.`);
    await renderTenants();
  } catch (err) {
    report(err);
  }
}

// ---------- security ----------

// renderSecurity lists people and their passkeys, and offers to add one.
async function renderSecurity() {
  const me = state.auth?.session;
  $("add-passkey-person").hidden = !!me?.person;
  $("ap-person").required = !me?.person;

  const host = $("security-host");
  const rpID = state.auth?.rp_id;
  host.hidden = !rpID || location.hostname === rpID;
  host.textContent = host.hidden ? "" : `Passkeys for this server only work at ${rpID}. Open the UI there to add one.`;

  const data = await api("GET", "/people");
  const people = data?.people || [];
  const box = clear($("people"));
  if (!people.length) {
    box.append(h("p", { class: "muted", text: "No one has a passkey yet. Until someone does, sign-in links from doh ui sign in on their own." }));
    return;
  }

  for (const person of people) {
    const mine = person.id === me?.person;
    const head = h("div", { class: "person-head" },
      h("h3", {}, person.name, mine ? h("span", { class: "badge you", text: "You" }) : null),
      h("span", { class: "badge", text: person.role }),
      isAdmin() ? h("button", { type: "button", class: "ghost danger-text", text: "Remove", "aria-label": `Remove ${person.name}`, onClick: () => removePerson(person, mine) }) : null,
    );
    const keys = h("ul", { class: "passkeys" }, person.passkeys.map((k) => h("li", { class: "passkey" },
      h("div", { class: "passkey-name" }, k.name, k.synced ? h("span", { class: "badge synced", text: "Synced", title: "A multi-device passkey, backed up to the person's account" }) : null),
      h("div", { class: "muted passkey-meta", text: `Added ${fmtTime(k.created, true)} · ${k.last_used ? "last used " + fmtTime(k.last_used, true) : "never used"}` }),
      isAdmin() ? h("button", { type: "button", class: "ghost danger-text", text: "Remove", "aria-label": `Remove passkey ${k.name}`, onClick: () => removePasskey(person, k, mine) }) : null,
    )));
    box.append(h("article", { class: "card person" }, head, keys));
  }
}

// addPasskey creates a passkey for the signed-in person, or for a link
// session, for a new person.
async function addPasskey(e) {
  e.preventDefault();
  const button = $("ap-submit");
  button.disabled = true;
  try {
    const name = $("ap-name").value.trim();
    const person = $("ap-person").value.trim();
    const begin = await authCall("POST", "/passkey/register", { name, person });
    const credential = await navigator.credentials.create({ publicKey: webauthnJSON.creationOptions(begin.options.publicKey) });
    const passkey = await authCall("POST", `/passkey/register/${encodeURIComponent(begin.id)}`, JSON.stringify(webauthnJSON.credential(credential)));
    $("ap-name").value = "";
    toast(`Added passkey ${passkey.name}.`);
    await refreshAuth();
    await renderSecurity();
  } catch (err) {
    if (err instanceof APIError && err.status === 401) showSignIn("Your session ended. Sign in again.");
    else toast(passkeyError(err), { error: true });
  } finally {
    button.disabled = false;
  }
}

async function removePasskey(person, passkey, mine) {
  const last = person.passkeys.length === 1;
  const warning = mine && last ? " It's your last passkey: you'll need a sign-in link to sign in again." : "";
  if (!(await confirmDialog(`Remove passkey ${passkey.name}?`, `It will no longer sign ${person.name} in.${warning}`))) return;
  try {
    await api("DELETE", `/people/${encodeURIComponent(person.id)}/passkeys/${encodeURIComponent(passkey.id)}`);
    toast(`Removed passkey ${passkey.name}.`);
    await renderSecurity();
  } catch (err) {
    report(err);
  }
}

async function removePerson(person, mine) {
  const text = mine
    ? "This removes your passkeys and signs you out everywhere."
    : `This removes their passkeys and signs them out everywhere.`;
  if (!(await confirmDialog(`Remove ${person.name}?`, text))) return;
  try {
    await api("DELETE", `/people/${encodeURIComponent(person.id)}`);
    if (mine) {
      state.auth = await authCall("GET", "/session").catch(() => state.auth);
      showSignIn("You removed yourself, and were signed out.");
      return;
    }
    toast(`Removed ${person.name}.`);
    await renderSecurity();
  } catch (err) {
    report(err);
  }
}

// ---------- wiring ----------

function wire() {
  $("signin-passkey").addEventListener("click", signInWithPasskey);
  $("signout").addEventListener("click", signOut);
  $("passkey-banner-go").addEventListener("click", () => show("security"));
  $("add-passkey").addEventListener("submit", addPasskey);
  for (const b of document.querySelectorAll(".nav")) b.addEventListener("click", () => show(b.dataset.view));
  $("new-profile").addEventListener("click", openCreate);
  $("new-tenant").addEventListener("click", openCreateTenant);
  $("tenant-form").addEventListener("submit", createTenant);
  $("tenant-cancel").addEventListener("click", () => $("tenant-dialog").close());
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
    if (/(?:^#|&)signin=/.test(location.hash)) start();
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("drawer").hidden) closeDrawer(); });
}

wire();
start();
