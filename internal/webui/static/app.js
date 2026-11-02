// doh admin UI. Plain ES module, no dependencies.
//
// Everything shown here can come from the network, and query names are
// chosen by whoever sends a query, so the DOM is only ever built with
// createElement and textContent: never from HTML strings.

import { fromNow, formatDate } from "./format.js";
import { Palette, looksLikeDomain } from "./palette.js";
import { drawRing, totalOf, hoursOf } from "./ring.js";
import { PRESETS, matchPreset, presetPatch, undoPatch } from "./presets.js";
import { currentTheme, applyTheme, nextTheme, themeLabel } from "./theme.js";
import { WEEKDAYS, DAY_NAMES, DAY_PRESETS, clockMinutes, overnight, scheduleActive, formatDays, describeBlocks, formatPeriod } from "./schedule.js";

const API = "/api/v1";
const AUTH = "/auth";
const LIVE_CAP = 500;

// The UI never holds an API token: the server signs the browser in with an
// HttpOnly session cookie, which fetch sends to this origin by itself.
const state = {
  auth: null, // the server's SessionStatus
  etag: "",
  status: null,
  catalog: { features: [], presets: [], services: [] },
  profiles: [],
  tenants: [], // every tenant for the operator, or the caller's own
  selected: "",
  view: "overview",
  readOnly: false,
  logNext: "",
  live: null, // AbortController of the live stream
  connect: { device: "", platform: "" }, // the "Connect a device" choices
  draft: null, // the schedule being added or edited, kept across renders
  appQuery: "", // the Apps search, kept across renders
  logScope: { since: "", until: "", reason: "" }, // what a link narrowed Activity to
  profileTab: "", // the profile editor's tab; empty for the profile's default
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

// count says how many of a thing there are: "1 list", "3 lists".
const count = (n, noun) => `${fmtNum(n)} ${noun}${n === 1 ? "" : "s"}`;

// badge returns a rounded square with someone's or something's initial,
// or an icon, as cards across the UI use to be told apart at a glance.
function badge(name, sym = "") {
  const initial = (String(name).match(/\p{L}|\p{N}/u)?.[0] || "?").toUpperCase();
  return h("span", { class: "id-badge", "aria-hidden": "true" }, sym ? icon(sym) : initial);
}

// icon returns one of the page's icons, by its symbol's ID without the
// "i-" prefix, hidden from assistive technology: what it means is always
// said in words beside it.
const SVG = "http://www.w3.org/2000/svg";
function icon(name, className = "") {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("class", ("icon " + className).trim());
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(SVG, "use");
  use.setAttribute("href", "#i-" + name);
  svg.append(use);
  return svg;
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

// toast tells someone what just happened. With an action, such as Undo,
// it stays longer, and pauses while pointed at or focused, so there's
// time to use it.
function toast(message, { error = false, details = [], action = null } = {}) {
  const body = h("div", { class: "toast-body" }, h("span", {}, message));
  if (details.length) body.append(h("ul", {}, details.map((d) => h("li", { text: d }))));
  const t = h("div", { class: "toast" + (error ? " error" : ""), role: error ? "alert" : "status" },
    icon(error ? "warn" : "check"), body);
  let timer;
  const dismiss = () => {
    clearTimeout(timer);
    t.classList.add("leaving");
    t.addEventListener("animationend", () => t.remove(), { once: true });
    setTimeout(() => t.remove(), 400); // without animations, go anyway
  };
  if (action) {
    t.append(h("button", { type: "button", class: "toast-action", text: action.label, onClick: async () => { dismiss(); await Promise.resolve(action.run()).catch(report); } }));
  }
  const wait = error ? 8000 : action ? 6500 : 3500;
  const arm = () => { clearTimeout(timer); timer = setTimeout(dismiss, wait); };
  t.addEventListener("pointerenter", () => clearTimeout(timer));
  t.addEventListener("pointerleave", arm);
  t.addEventListener("focusin", () => clearTimeout(timer));
  t.addEventListener("focusout", arm);
  $("toasts").append(t);
  arm();
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
  $("signin-passkey-label").textContent = pending ? "Continue with a passkey" : "Sign in with a passkey";
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
  const name = s?.name || "";
  const role = [s?.role === "reader" ? "Reader" : "Admin", tenant ? tenantName(tenant) : isOperator() ? "Operator" : ""].filter(Boolean).join(" · ");
  const initial = (name.match(/\p{L}|\p{N}/u)?.[0] || "?").toUpperCase();
  // A link sign-in isn't anyone yet: a key, not an initial.
  const face = () => s?.person ? document.createTextNode(initial) : icon("key");
  for (const box of [$("who"), $("who-mobile")]) {
    clear(box).append(
      h("span", { class: "avatar", "aria-hidden": "true" }, face()),
      h("span", { class: "who-text" }, h("span", { class: "who-name", text: name, title: name }), h("span", { class: "who-role", text: role })),
    );
  }
  clear($("avatar")).append(face());
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
  state.catalog = { features: [], presets: [], services: [], ...catalog };
  setReadOnly(status.policy);
  await Promise.all([loadPolicy(), loadTenants()]);
  // Only the operator manages tenants and sees how the server runs.
  $("nav-tenants").hidden = !isOperator();
  $("list-health-card").hidden = !isOperator();
  renderWho();
  $("signin").hidden = true;
  $("app").hidden = false;
  applyRoute();
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

// ---------- routing ----------
//
// Every view has a URL, #/view or #/view/argument, so back, forward,
// reload, and links work. Sign-in links use #signin=..., handled apart.

const VIEWS = ["overview", "profiles", "logs", "explain", "security", "tenants"];

// parseRoute reads the view and its argument, such as a profile ID, from
// a URL hash.
function parseRoute(hash = location.hash) {
  const m = /^#\/([a-z]+)(?:\/([^?]*))?(?:\?(.*))?$/.exec(hash);
  if (!m || !VIEWS.includes(m[1])) return { view: "overview", arg: "", query: new URLSearchParams() };
  let arg = "";
  try { arg = decodeURIComponent(m[2] || ""); } catch { /* a malformed link: ignore its argument */ }
  return { view: m[1], arg, query: new URLSearchParams(m[3] || "") };
}

// routeHash returns the URL hash of a view, its argument, and its query,
// leaving out empty query values.
function routeHash(view, arg = "", query = {}) {
  const q = new URLSearchParams(Object.entries(query).filter(([, v]) => v !== undefined && v !== ""));
  return `#/${view}${arg ? "/" + encodeURIComponent(arg) : ""}${q.size ? "?" + q : ""}`;
}

// go navigates to a view, adding to history.
function go(view, arg = "", query = {}) {
  const hash = routeHash(view, arg, query);
  if (location.hash === hash) applyRoute();
  else location.hash = hash;
}

// setRoute records where the page is without rendering again, such as
// after creating a profile that's already shown.
function setRoute(view, arg = "", query = {}) {
  history.replaceState(null, "", routeHash(view, arg, query));
}

// applyRoute shows what the URL names.
function applyRoute() {
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

function show(view) {
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

// SECURITY_REASONS are the checks that stop attacks rather than apply
// someone's preferences, so the Overview can count threats apart.
const SECURITY_REASONS = new Set(["homograph", "tunneling", "rebinding", "newly-registered", "bypass"]);

// startOfToday returns local midnight.
function startOfToday(now = new Date()) {
  return new Date(now.getFullYear(), now.getMonth(), now.getDate());
}

// hourRange describes an hour of the clock, such as "7–8 PM".
function hourRange(h) {
  const fmt = new Intl.DateTimeFormat(undefined, { hour: "numeric" });
  const at = (x) => fmt.format(new Date(2000, 0, 1, x));
  return `${at(h)}–${at((h + 1) % 24)}`;
}

const plural = (n, one, many = one + "s") => `${fmtNum(n)} ${n === 1 ? one : many}`;

// renderOverview shows today: the day as a ring, a plain verdict, what
// needs someone, and where queries went. Every number opens the queries
// behind it.
async function renderOverview() {
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

// buddy returns the character in a mood: "calm" or "alert".
function buddy(mood) {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("class", "buddy");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(SVG, "use");
  use.setAttribute("href", "#buddy-" + mood);
  svg.append(use);
  return svg;
}

// attentionItems lists what needs someone today, each with what to do.
function attentionItems(status, stats, since) {
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
function renderServer(status) {
  const info = clear($("server-info"));
  const kv = (k, v) => info.append(h("dt", { text: k }), h("dd", {}, v));
  if (!isOperator()) {
    $("server-title").textContent = "Your tenant";
    $("server-summary").textContent = tenantName(status.tenant);
    kv("Tenant", tenantName(status.tenant));
    kv("Profiles", fmtNum(status.policy?.profiles));
    kv("Activity", status.query_log?.enabled ? "kept" : "off");
    kv("Version", status.version || "—");
    return;
  }
  const up = status.started ? fmtDuration(Date.now() - new Date(status.started)) : "";
  const failed = (status.lists || []).filter((l) => l.error).length;
  $("server-summary").textContent = [status.version, up && `up ${up}`, `${plural((status.lists || []).length, "list")}${failed ? `, ${failed} failed` : ""}`].filter(Boolean).join(" · ");
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

// ---------- profiles ----------

function renderProfiles() {
  const cards = clear($("profile-cards"));
  for (const p of state.profiles) {
    const name = p.name || p.id;
    const initial = (name.match(/\p{L}|\p{N}/u)?.[0] || "?").toUpperCase();
    cards.append(
      h("button", { type: "button", class: "card profile-card", "aria-pressed": String(p.id === state.selected), onClick: () => selectProfile(p.id) },
        h("span", { class: "profile-initial", "aria-hidden": "true", text: initial }),
        h("span", { class: "profile-card-body" },
          h("span", { class: "profile-card-name" }, name, isOperator() && p.tenant ? h("span", { class: "badge tenant", text: tenantName(p.tenant) }) : null),
          h("span", { class: "profile-meta", text: profileSummary(p) }),
          p.name ? h("span", { class: "profile-meta mono", text: p.id }) : null,
        ),
      ),
    );
  }
  if (!state.profiles.length) cards.append(h("p", { class: "muted", text: "No profiles: every client is refused. Create a profile named \"default\" to serve everyone else." }));
  renderEditor();
}

function selectProfile(id) {
  go("profiles", state.selected === id ? "" : id);
  if (state.selected) requestAnimationFrame(() => $("profile-editor").scrollIntoView({ behavior: "smooth", block: "start" }));
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

// switchControl renders a switch that applies makePatch(on) immediately.
function switchControl(label, checked, makePatch) {
  const input = edit(h("input", { type: "checkbox", role: "switch", checked, "aria-label": label }));
  input.addEventListener("change", async () => {
    input.disabled = true;
    const ok = await patchProfile(state.selected, makePatch(input.checked));
    if (!ok) input.checked = !input.checked;
  });
  return input;
}

// toggleRow renders a titled, described switch that applies a patch
// immediately.
function toggleRow(title, desc, checked, makePatch, extra) {
  const input = switchControl(title, checked, makePatch);
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

  return h("div", {},
    section("Connect a device",
      "Point a phone, tablet, or computer at this profile. The profile ID isn't a secret: anyone who knows it can use this profile.",
      deviceRow, body),
    sendSection(p, () => (validDevice(device.value.trim().toLowerCase()) ? device.value.trim().toLowerCase() : "")));
}

// qrCode shows the server's QR code as an image: an image runs no
// scripts, and the page's policy allows data: images.
function qrCode(q, label) {
  return h("img", { class: "qr", src: `data:image/svg+xml,${encodeURIComponent(q.svg)}`, alt: label, width: 176, height: 176 });
}

// sendSection makes a short-lived link to a setup page for the device to
// open itself: shared over AirDrop or a message, or copied.
function sendSection(p, deviceName) {
  const out = h("div", { class: "send-result", "aria-live": "polite" });
  const make = edit(h("button", { type: "button", class: "primary" }, icon("arrow"), "Create a setup link"));
  make.addEventListener("click", async () => {
    make.disabled = true;
    try {
      const link = await api("POST", `/profiles/${encodeURIComponent(p.id)}/setup-links`, { query: { device: deviceName() } });
      const url = h("output", { class: "send-url mono", text: link.url });
      const copy = h("button", { type: "button" }, icon("copy"), "Copy");
      copy.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(link.url); toast("Copied the setup link."); } catch { toast("Select the link and copy it."); }
      });
      const share = navigator.share
        ? h("button", { type: "button", class: "primary" }, icon("arrow"), "Share")
        : null;
      share?.addEventListener("click", () => navigator.share({ title: `Set up ${p.name || p.id}`, url: link.url }).catch(() => {}));
      const until = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(new Date(link.expires));
      // Node.append would write a missing part as the text "null".
      clear(out).append(...[
        link.qr && h("div", { class: "send-qr" }, qrCode(link.qr, `QR code for the setup link for ${p.name || p.id}`),
          h("p", {}, h("strong", { text: "Scan it with the device's camera" }), h("span", { class: "muted", text: ` or open the link there. It works until ${until}.` }))),
        url,
        h("div", { class: "send-actions" }, share, copy),
        !link.qr && h("p", { class: "muted hint", text: `Open it on the device itself. It works until ${until}.` }),
      ].filter(Boolean));
    } catch (err) {
      clear(out).append(h("p", { class: "muted", text: err.status === 409
        ? (isOperator() ? "Setup links need this server's public name and DoH: start it with --hostname and a certificate." : "Setup links aren't available on this server yet. Ask its operator.")
        : err.message }));
    } finally {
      make.disabled = state.readOnly;
    }
  });
  return section("Send to a device",
    "A link to open on the phone or tablet you're setting up, with one-tap install on Apple devices. It works for 30 minutes.",
    make, out);
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

// PROFILE_TABS are the profile editor's tabs: what each holds, and how
// many things it has turned on, for its badge.
const PROFILE_TABS = [
  { id: "connect", title: "Connect", icon: "arrow", count: () => 0 },
  { id: "protection", title: "Protection", icon: "security", count: (p) => Object.values(p.security || {}).filter((v) => v === true).length + (p.lists || []).length + (p.safe_search ? 1 : 0) },
  { id: "apps", title: "Apps & schedules", icon: "block", count: (p) => (p.services || []).length + (p.schedules || []).length },
  { id: "rules", title: "Allow & deny", icon: "allow", count: (p) => (p.allow || []).length + (p.deny || []).length + (p.block_tlds || []).length },
  { id: "devices", title: "Devices", icon: "system", count: (p) => (p.devices || []).length + (p.clients || []).length + (p.rewrites || []).length },
  { id: "settings", title: "Settings", icon: "profiles", count: () => 0 },
];

// defaultTab is where a profile opens: how to connect a device, for one
// no device uses yet, and otherwise its protection.
const defaultTab = (p) => (!(p.devices || []).length && !(p.clients || []).length && p.id !== "default" ? "connect" : "protection");

// profileSummary says in a line what a profile does.
function profileSummary(p) {
  const on = Object.values(p.security || {}).filter((v) => v === true).length + (p.safe_search ? 1 : 0);
  return [
    count(on, "protection"),
    count((p.lists || []).length, "list"),
    (p.services || []).length ? `${count(p.services.length, "app")} blocked` : null,
    (p.schedules || []).length ? count(p.schedules.length, "schedule") : null,
    count((p.devices || []).length, "device"),
  ].filter(Boolean).join(" · ");
}

function renderEditor() {
  const box = $("profile-editor");
  const p = profile();
  box.hidden = !p;
  clear(box);
  if (!p) return;

  const tab = PROFILE_TABS.some((t) => t.id === state.profileTab) ? state.profileTab : defaultTab(p);
  const card = h("div", { class: "card editor" });
  box.append(card);

  card.append(h("div", { class: "editor-head" },
    h("div", { class: "editor-title" },
      h("h2", { text: p.name || p.id }),
      h("p", { class: "muted editor-sub" },
        h("span", { class: "mono", text: p.id }),
        isOperator() && p.tenant ? h("span", { class: "badge tenant", text: tenantName(p.tenant) }) : null,
        h("span", { text: profileSummary(p) })),
    ),
  ));

  // The tabs: a tablist with arrow keys between tabs, each a URL.
  const tabs = h("div", { class: "tabs-strip", role: "tablist", "aria-label": `${p.name || p.id} settings` });
  for (const t of PROFILE_TABS) {
    const n = t.count(p);
    const b = h("button", {
      type: "button", role: "tab", id: `tab-${t.id}`, "aria-selected": String(t.id === tab), "aria-controls": "profile-panel",
      tabindex: t.id === tab ? 0 : -1, onClick: () => openTab(p.id, t.id),
    }, icon(t.icon), h("span", { text: t.title }), n ? h("span", { class: "tab-count", text: fmtNum(n), "aria-label": `, ${n} on` }) : null);
    tabs.append(b);
  }
  tabs.addEventListener("keydown", (e) => {
    const all = [...tabs.querySelectorAll("[role=tab]")];
    const i = all.indexOf(document.activeElement);
    const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: all.length - 1 }[e.key];
    if (next === undefined || i < 0) return;
    e.preventDefault();
    const t = all[(next + all.length) % all.length];
    t.focus();
    t.click();
  });
  const panel = h("div", { class: "tab-panel", id: "profile-panel", role: "tabpanel", "aria-labelledby": `tab-${tab}` });
  card.append(tabs, panel);
  panel.append(...{ connect: connectTab, protection: protectionTab, apps: appsTab, rules: rulesTab, devices: devicesTab, settings: settingsTab }[tab](p));
  requestAnimationFrame(() => tabs.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: "nearest", inline: "nearest" }));
}

// openTab shows one of a profile's tabs, in the URL too.
function openTab(id, tab) {
  state.profileTab = tab;
  setRoute("profiles", id, { tab });
  renderEditor();
  document.getElementById(`tab-${tab}`)?.focus({ preventScroll: true });
}

function connectTab(p) {
  return [connectSection(p)];
}

function protectionTab(p) {
  const id = p.id;
  const sec = p.security || {};
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
  const lists = p.lists || [];
  const presets = state.catalog.presets || [];
  const presetNames = new Set(presets.map((x) => x.name));
  const listToggle = (pr) => toggleRow(pr.title, pr.description, lists.includes(pr.name), (on) => ({
    lists: on ? [...(profile().lists || []), pr.name] : (profile().lists || []).filter((l) => l !== pr.name),
  }));
  const group = (cat) => h("div", { class: "toggle-list" }, presets.filter((x) => x.category === cat).map(listToggle));
  const custom = lists.filter((l) => !presetNames.has(l) && l !== "default");
  const current = matchPreset(p);
  const fine = h("details", { class: "fine-tune", open: current === "" },
    h("summary", {}, h("span", { text: "Fine-tune" }), h("span", { class: "muted", text: current ? "Every protection and list, one by one" : "Your own mix of protections and lists" })),
    section("Security", "Built-in protections. Changes apply to new queries at once.",
      h("div", { class: "toggle-list" }, feats.filter((f) => f.category !== "parental").map(featToggle))),
    section("Threat lists", "Blocklists of known-bad domains.", group("security")),
    section("Privacy", "Ads and trackers.", group("privacy")),
    section("Parental", "Content some households restrict.",
      h("div", { class: "toggle-list" }, feats.filter((f) => f.category === "parental").map(featToggle)), group("parental")),
  );
  return [levelSection(p, current), fine, customListsSection(p, custom, lists)];
}

// levelSection offers the protection presets as a choice of levels,
// applied at once with Undo.
function levelSection(p, current) {
  const group = h("div", { class: "levels", role: "radiogroup", "aria-label": "Protection level" });
  for (const preset of PRESETS) {
    const on = preset.id === current;
    const b = edit(h("button", {
      type: "button", class: "level", role: "radio", "aria-checked": String(on),
      onClick: () => applyPreset(p, preset),
    },
    h("span", { class: "level-head" }, h("strong", { text: preset.name }), on ? icon("check") : null),
    h("span", { class: "level-line", text: preset.line })));
    group.append(b);
  }
  // Arrow keys move between levels, as in any radio group.
  group.addEventListener("keydown", (e) => {
    const all = [...group.querySelectorAll(".level")];
    const i = all.indexOf(document.activeElement);
    const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
    if (i < 0 || !step) return;
    e.preventDefault();
    all[(i + step + all.length) % all.length].focus();
  });
  return section("Protection level", current ? "" : "This profile has its own mix. Choose a level to start again from it.", group);
}

async function applyPreset(p, preset) {
  const before = undoPatch(p);
  if (!(await patchProfile(p.id, presetPatch(p, preset)))) return;
  toast(`${p.name || p.id} is now at ${preset.name}.`, {
    action: { label: "Undo", run: async () => { if (await patchProfile(p.id, before)) toast("Put back as it was."); } },
  });
}

function appsTab(p) {
  return [appsSection(p), schedulesSection(p)];
}

function rulesTab(p) {
  const id = p.id;
  const refresh = (pp) => { renderProfiles(); return pp; };
  return [
    section("Allowed domains", "Never blocked by anything in this profile, with their subdomains.",
      chipEditor(p.allow, "example.com", "Allow domain", (v) => domainAction(id, "allow", v).then(refresh), (v) => domainAction(id, "allow", v, true).then(refresh))),
    section("Denied domains", "Always blocked, with their subdomains.",
      chipEditor(p.deny, "example.com", "Deny domain", (v) => domainAction(id, "deny", v).then(refresh), (v) => domainAction(id, "deny", v, true).then(refresh))),
    section("Blocked TLDs", "Every name under these top-level domains.",
      chipEditor(p.block_tlds, "zip", "Block TLD",
        (v) => patchProfile(id, { block_tlds: [...(p.block_tlds || []), v.replace(/^\./, "")] }),
        (v) => patchProfile(id, { block_tlds: (p.block_tlds || []).filter((t) => t !== v) }))),
  ];
}

function devicesTab(p) {
  const id = p.id;
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

  return [
    section("Devices", "Named clients. Their addresses select this profile, and logs show their names.", bounds, devRows, devForm),
    section("Networks", "Addresses or prefixes whose queries use this profile. The most specific match wins.", bounds?.cloneNode(true),
      chipEditor(p.clients, "192.168.1.0/24", "Client prefix",
        (v) => patchProfile(id, { clients: [...(p.clients || []), v] }),
        (v) => patchProfile(id, { clients: (p.clients || []).filter((c) => c !== v) }))),
    section("Rewrites", "Answer names locally, such as a home server with its LAN address. Use *.domain for subdomains.", rwRows, rwForm),
  ];
}

function settingsTab(p) {
  const id = p.id;
  const name = edit(h("input", { value: p.name || "", "aria-label": "Profile name" }));
  const nameForm = h("form", { class: "chip-form" }, name, edit(h("button", { type: "submit", text: "Rename" })));
  nameForm.addEventListener("submit", (e) => { e.preventDefault(); patchProfile(id, { name: name.value.trim() }); });

  const resp = edit(h("select", { "aria-label": "Block response" },
    h("option", { value: "nxdomain", text: "NXDOMAIN (name doesn't exist)" }),
    h("option", { value: "null", text: "Null address (0.0.0.0 and ::)" })));
  resp.value = p.block_response || "nxdomain";
  resp.addEventListener("change", () => patchProfile(id, { block_response: resp.value }));

  return [
    section("Name", "", nameForm),
    section("Behavior", "",
      h("div", { class: "toggle-list" },
        h("div", { class: "toggle" }, h("div", { class: "title", text: "Block response" }), h("div", { class: "control" }, resp), h("div", { class: "desc", text: "How blocked names are answered." })),
        toggleRow("Don't log this profile", "Keep its queries out of Activity. They're still counted in metrics.", !!p.logging?.disabled, (on) => ({ logging: { disabled: on } })),
      )),
    section("Delete this profile", p.id === "default"
      ? "Its devices fall back to other profiles. Without a default profile, clients that match no other profile are refused."
      : "Its devices fall back to other profiles, such as the default.",
    edit(h("button", { type: "button", class: "danger", text: `Delete ${p.name || p.id}`, onClick: () => deleteProfile(p) }))),
  ];
}

// ---------- apps and schedules ----------

const CATEGORIES = [
  ["social", "Social"], ["messaging", "Messaging"], ["video", "Video and streaming"], ["music", "Music"],
  ["gaming", "Gaming"], ["ai", "AI chat"], ["shopping", "Shopping"], ["dating", "Dating"], ["gambling", "Gambling and betting"],
];

const services = () => state.catalog.services || [];
const serviceName = (id) => services().find((s) => s.id === id)?.name || id;
const listTitle = (name) => state.catalog.presets?.find((x) => x.name === name)?.title || name;
const blockNames = (kind, id) => (kind === "service" ? serviceName(id) : listTitle(id));

// appsSection toggles the services a profile always blocks, by category,
// with a search that narrows the catalog as you type.
function appsSection(p) {
  const blocked = p.services || [];
  const known = new Set(services().map((s) => s.id));
  const groups = CATEGORIES.map(([cat, title]) => {
    const list = services().filter((s) => s.category === cat);
    if (!list.length) return null;
    return h("fieldset", { class: "app-group" }, h("legend", { text: title }),
      list.map((s) => h("label", { class: "app", "data-search": `${s.name} ${s.id} ${title}`.toLowerCase() },
        h("span", { class: "app-name", text: s.name }),
        switchControl(`Block ${s.name}`, blocked.includes(s.id), (on) => {
          const cur = profile().services || [];
          return { services: on ? [...cur, s.id] : cur.filter((x) => x !== s.id) };
        }),
      )));
  }).filter(Boolean);

  const grid = h("div", { class: "app-groups" }, groups);
  const none = h("p", { class: "muted", text: "No apps match.", hidden: true });
  const search = h("input", {
    type: "search", class: "app-search", placeholder: `Search ${services().length} apps`,
    "aria-label": "Search apps", value: state.appQuery || "",
  });
  const narrow = () => {
    const q = (state.appQuery = search.value.trim().toLowerCase());
    let shown = 0;
    for (const g of groups) {
      let any = false;
      for (const app of g.querySelectorAll(".app")) {
        app.hidden = q !== "" && !app.dataset.search.includes(q);
        any ||= !app.hidden;
      }
      g.hidden = !any;
      shown += any ? 1 : 0;
    }
    none.hidden = shown > 0;
  };
  search.addEventListener("input", narrow);
  narrow();

  const summary = blocked.length
    ? `Blocked: ${blocked.map(serviceName).join(", ")}.`
    : "Nothing blocked by name yet.";
  const unknown = blocked.filter((id) => !known.has(id));
  return section("Apps", "Block apps and sites by name, with the domains they use. Apps change their domains, so this is a best effort: deny any that slip through.",
    h("p", { class: "field-note", text: summary }),
    search, none, grid,
    unknown.length ? h("p", { class: "field-note", text: `Also blocked, but no longer in the catalog: ${unknown.join(", ")}.` }) : null);
}

// schedulesSection lists a profile's schedules, marks those in effect
// now, and adds, edits, and deletes them.
function schedulesSection(p) {
  const id = p.id;
  const schedules = p.schedules || [];
  if (state.draft && state.draft.profile !== id) state.draft = null;

  const now = new Date();
  const rows = h("div", { class: "schedules" });
  for (const sc of schedules) {
    const active = scheduleActive(sc, now, p.time_zone);
    rows.append(h("div", { class: "schedule" + (active ? " active" : "") },
      h("div", { class: "schedule-head" },
        h("strong", { text: sc.name }),
        active ? h("span", { class: "badge active", text: "Active now" }) : null,
      ),
      h("div", { class: "schedule-when" },
        `${formatDays(sc.days)} · ${formatPeriod(sc)}`,
        overnight(sc) ? h("span", { class: "muted", text: " next morning" }) : null),
      h("div", { class: "muted", text: `Blocks ${describeBlocks(sc, blockNames)}` }),
      h("div", { class: "schedule-actions" },
        edit(h("button", { type: "button", class: "small", text: "Edit", "aria-label": `Edit ${sc.name}`, onClick: () => { state.draft = draftFrom(id, sc); renderEditor(); focusDraft(); } })),
        edit(h("button", { type: "button", class: "small danger-text", text: "Delete", "aria-label": `Delete ${sc.name}`, onClick: () => deleteSchedule(p, sc) })),
      ),
    ));
  }
  if (!schedules.length) rows.append(h("span", { class: "muted", text: "No schedules." }));

  const notes = [];
  if (schedules.length && !p.time_zone) notes.push(h("p", { class: "field-note", text: "Set a time zone to see which schedules are in effect now." }));

  const body = state.draft
    ? scheduleForm(p, state.draft)
    : edit(h("button", { type: "button", text: "Add schedule", onClick: () => { state.draft = draftFrom(id); renderEditor(); focusDraft(); } }));
  return section("Schedules", "Block more at certain times, such as games during homework or everything but school sites at bedtime.",
    timeZoneField(p), rows, ...notes, body);
}

// draftFrom starts a schedule draft for profile id, from sc when editing.
function draftFrom(id, sc) {
  return {
    profile: id,
    editing: sc?.name ?? null,
    name: sc?.name || "",
    days: sc?.days?.length ? [...sc.days] : [...WEEKDAYS],
    start: sc?.start || "21:00",
    end: sc?.end || "07:00",
    blockAll: sc ? !!sc.block_all : true,
    allow: [...(sc?.allow || [])],
    services: [...(sc?.services || [])],
    lists: [...(sc?.lists || [])],
    deny: [...(sc?.deny || [])],
  };
}

function focusDraft() {
  $("sc-name")?.focus();
}

// draftSchedule turns a draft into a schedule as the API takes it, or
// returns the problems with it.
function draftSchedule(d, existing) {
  const errors = [];
  const name = d.name.trim();
  if (!name) errors.push("Name the schedule, such as Bedtime.");
  else if (existing.some((s) => s.name.toLowerCase() === name.toLowerCase() && s.name !== d.editing)) errors.push(`There's already a schedule named ${name}.`);
  if (!d.days.length) errors.push("Choose at least one day.");
  const start = clockMinutes(d.start);
  const end = clockMinutes(d.end);
  if (Number.isNaN(start) || Number.isNaN(end)) errors.push("Choose a start and end time.");
  if (!d.blockAll && !d.services.length && !d.lists.length && !d.deny.length) errors.push("Choose something to block.");
  if (errors.length) return { errors };

  const sc = { name, start: d.start, end: d.end };
  if (d.days.length < 7) sc.days = WEEKDAYS.filter((x) => d.days.includes(x));
  if (d.blockAll) {
    sc.block_all = true;
    if (d.allow.length) sc.allow = d.allow;
  } else {
    for (const k of ["services", "lists", "deny"]) if (d[k].length) sc[k] = d[k];
  }
  return { schedule: sc };
}

// scheduleForm edits the draft d, which outlives re-renders.
function scheduleForm(p, d) {
  const errors = h("div", { class: "field-error", role: "alert" });
  const name = edit(h("input", { id: "sc-name", value: d.name, placeholder: "Bedtime", maxlength: 64, autocomplete: "off" }));
  name.addEventListener("input", () => { d.name = name.value; });

  // Days: a chip per day, and presets.
  const days = h("div", { class: "day-chips", role: "group", "aria-label": "Days" });
  const renderDays = () => {
    clear(days);
    WEEKDAYS.forEach((day, i) => {
      days.append(edit(h("button", {
        type: "button", class: "day", text: DAY_NAMES[i][0], title: DAY_NAMES[i],
        "aria-label": DAY_NAMES[i], "aria-pressed": String(d.days.includes(day)),
        onClick: () => {
          d.days = d.days.includes(day) ? d.days.filter((x) => x !== day) : WEEKDAYS.filter((x) => x === day || d.days.includes(x));
          renderDays();
        },
      })));
    });
    for (const [label, set] of DAY_PRESETS) {
      const on = set.length === d.days.length && set.every((x) => d.days.includes(x));
      days.append(edit(h("button", { type: "button", class: "small preset", text: label, "aria-pressed": String(on), onClick: () => { d.days = [...set]; renderDays(); } })));
    }
  };
  renderDays();

  // Times, with a note when the period runs past midnight.
  const start = edit(h("input", { type: "time", id: "sc-start", value: d.start, required: true }));
  const end = edit(h("input", { type: "time", id: "sc-end", value: d.end, required: true }));
  const night = h("p", { class: "field-note", "aria-live": "polite" });
  const renderNight = () => {
    const start = clockMinutes(d.start), end = clockMinutes(d.end);
    night.textContent = end === start ? "Lasts all day." : end < start ? "Runs past midnight into the next morning." : "";
  };
  start.addEventListener("input", () => { d.start = start.value; renderNight(); });
  end.addEventListener("input", () => { d.end = end.value; renderNight(); });
  renderNight();

  // What it blocks: everything but some sites, or some apps and lists.
  const mode = h("div", { class: "mode-panel" });
  const radio = (value, label) => {
    const input = edit(h("input", { type: "radio", name: "sc-mode", value, checked: d.blockAll === (value === "all") }));
    input.addEventListener("change", () => { d.blockAll = value === "all"; renderMode(); });
    return h("label", { class: "radio" }, input, label);
  };
  const renderMode = () => {
    clear(mode);
    if (d.blockAll) {
      mode.append(
        h("p", { class: "field-note", text: "The profile's allowed domains and names on your network keep working." }),
        draftChips(d.allow, "school.example", "Allow during this schedule"));
      return;
    }
    const checks = (kind, items) => h("div", { class: "check-grid" + (items.length > 24 ? " scroll" : "") }, items.map(([value, label]) => {
      const input = edit(h("input", { type: "checkbox", checked: d[kind].includes(value) }));
      input.addEventListener("change", () => { d[kind] = input.checked ? [...d[kind], value] : d[kind].filter((x) => x !== value); });
      return h("label", { class: "check" }, input, label);
    }));
    mode.append(
      h("fieldset", { class: "sub" }, h("legend", { text: "Apps" }), checks("services", services().map((s) => [s.id, s.name]))),
      h("fieldset", { class: "sub" }, h("legend", { text: "Lists" }), checks("lists", (state.catalog.presets || []).filter((x) => x.category !== "security").map((x) => [x.name, x.title]))),
      h("fieldset", { class: "sub" }, h("legend", { text: "Domains" }), draftChips(d.deny, "games.example", "Block during this schedule")),
    );
  };
  renderMode();

  const form = h("form", { class: "schedule-form", "aria-label": d.editing ? `Edit ${d.editing}` : "Add schedule", novalidate: true },
    h("h4", { text: d.editing ? `Edit ${d.editing}` : "Add a schedule" }),
    h("label", { class: "field" }, h("span", { text: "Name" }), name),
    h("div", { class: "field" }, h("span", { text: "Days it starts on" }), days),
    h("div", { class: "times" },
      h("label", { class: "field" }, h("span", { text: "Starts" }), start),
      h("label", { class: "field" }, h("span", { text: "Ends" }), end)),
    night,
    h("fieldset", { class: "mode" }, h("legend", { text: "Blocks" }),
      radio("all", "Block everything except…"), radio("some", "Block these"), mode),
    errors,
    h("div", { class: "actions" },
      edit(h("button", { type: "submit", class: "primary", text: d.editing ? "Save schedule" : "Add schedule" })),
      h("button", { type: "button", text: "Cancel", onClick: () => { state.draft = null; renderEditor(); } })),
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const existing = profile()?.schedules || [];
    const { schedule, errors: problems } = draftSchedule(d, existing);
    if (problems) {
      errors.replaceChildren(...problems.map((m) => h("div", { text: m })));
      return;
    }
    const next = d.editing === null
      ? [...existing, schedule]
      : existing.map((s) => (s.name === d.editing ? schedule : s));
    if (await patchProfile(p.id, { schedules: next })) {
      state.draft = null;
      renderEditor();
      toast(`${d.editing === null ? "Added" : "Saved"} ${schedule.name}`);
    }
  });
  return form;
}

// draftChips edits values, an array in a draft, in place.
function draftChips(values, placeholder, label) {
  const chips = h("div", { class: "chips" });
  const render = () => {
    clear(chips);
    for (const v of values) {
      chips.append(h("span", { class: "chip" }, v, edit(h("button", {
        type: "button", "aria-label": `Remove ${v}`, text: "✕",
        onClick: () => { values.splice(values.indexOf(v), 1); render(); },
      }))));
    }
  };
  render();
  const input = edit(h("input", { placeholder, "aria-label": label, spellcheck: "false", autocomplete: "off" }));
  const add = () => {
    const v = input.value.trim().toLowerCase().replace(/\.$/, "");
    if (v && !values.includes(v)) values.push(v);
    input.value = "";
    render();
  };
  // Enter adds a domain here rather than submitting the schedule.
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); add(); } });
  return h("div", {}, chips, h("div", { class: "chip-form" }, input, edit(h("button", { type: "button", text: "Add", onClick: add }))));
}

async function deleteSchedule(p, sc) {
  if (!(await confirmDialog(`Delete ${sc.name}?`, `${formatDays(sc.days)}, ${formatPeriod(sc)}. It stops blocking at once.`))) return;
  const next = (profile()?.schedules || []).filter((s) => s.name !== sc.name);
  if (await patchProfile(p.id, { schedules: next.length ? next : null })) toast(`Deleted ${sc.name}`);
}

// browserTimeZone returns the time zone this browser is in, if it says.
function browserTimeZone() {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch { return ""; }
}

// timeZoneField picks the IANA time zone a profile's schedules follow.
// Blank is the server's local time.
function timeZoneField(p) {
  const cur = p.time_zone || "";
  const save = (tz) => patchProfile(p.id, { time_zone: tz || null });
  let zones = [];
  try { zones = Intl.supportedValuesOf("timeZone"); } catch { /* an older browser: type it instead */ }

  let control;
  if (zones.length) {
    if (cur && !zones.includes(cur)) zones = [cur, ...zones];
    control = edit(h("select", { id: "sc-tz" },
      h("option", { value: "", text: "Server's local time" }),
      zones.map((z) => h("option", { value: z, text: z.replaceAll("_", " ") }))));
    control.value = cur;
    control.addEventListener("change", () => save(control.value));
  } else {
    const input = edit(h("input", { id: "sc-tz", value: cur, placeholder: "America/New_York", spellcheck: "false", autocomplete: "off" }));
    control = h("form", { class: "chip-form" }, input, edit(h("button", { type: "submit", text: "Save" })));
    control.addEventListener("submit", (e) => { e.preventDefault(); save(input.value.trim()); });
  }

  const browser = browserTimeZone();
  return h("div", { class: "tz" },
    h("label", { for: "sc-tz", text: "Time zone" }),
    h("div", { class: "tz-control" }, control,
      browser && browser !== cur ? edit(h("button", { type: "button", class: "small", text: `Use this browser's time zone (${browser})`, onClick: () => save(browser) })) : null),
  );
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

// confirmDialog asks before something that can't be undone, naming the
// action on its button: "Delete", "Revoke", "Remove".
function confirmDialog(title, text, action = "Delete") {
  const dlg = $("confirm-dialog");
  $("confirm-title").textContent = title;
  $("confirm-text").textContent = text;
  $("confirm-ok").textContent = action;
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
    setRoute("profiles");
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
    setRoute("profiles", p.id);
    fillProfileSelects();
    renderProfiles();
    toast(`Created ${p.id}`);
  } catch (err) {
    report(err);
  }
}

// ---------- query log ----------

// logFilter returns the Activity view's filter: what its form says, and
// the time window and reason a link narrowed it to.
function logFilter() {
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
function setLogFilter(q) {
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
function renderLogScope() {
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
function applyLogFilter() {
  setRoute("logs", "", logFilter());
  renderLogScope();
  if (state.live) startLive();
  else loadLogs(true).catch(report);
}

// CHECKS are the names, for people, of the policy checks that decisions'
// reasons and explanations' timelines give by ID.
const CHECKS = {
  upstream: "Upstream", local: "Local name", rewrite: "Rewrite", allow: "Allowed domains", deny: "Denied domains",
  service: "Blocked apps", schedule: "Schedules", bypass: "Bypass protection", tld: "Blocked TLDs", list: "Blocklists",
  homograph: "Look-alike names", tunneling: "DNS tunneling", "newly-registered": "Newly registered domains",
  "safe-search": "Safe search", rebinding: "DNS rebinding", cname: "CNAME targets", resolved: "Resolved",
};
const checkName = (id) => CHECKS[id] || id;

// reasonText says briefly why a query was decided as it was, naming the
// app or schedule that blocked it.
function reasonText(e) {
  if (e.reason === "service" && e.source) return `App: ${serviceName(e.source)}`;
  if (e.reason === "schedule" && e.source) return `Schedule: ${e.source}`;
  if (e.reason === "list" && e.source) return `Blocklist: ${listTitle(e.source)}`;
  return e.reason ? checkName(e.reason) : "";
}

// STATUS_WORDS say each status in words, with a symbol, so it never
// rests on color.
const STATUS_WORDS = { allowed: ["Allowed", "allow"], blocked: ["Blocked", "block"], rewritten: ["Rewritten", "arrow"], error: ["Failed", "warn"] };

function statusPill(status) {
  const [word, sym] = STATUS_WORDS[status] || [status, "arrow"];
  return h("span", { class: `pill ${status}` }, icon(sym), word);
}

function logRow(e) {
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
let logSeq = 0;
async function loadLogs(reset) {
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

function openDrawer(e) {
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

function closeDrawer() {
  $("drawer").hidden = true;
}

// ---------- explain ----------

// EXPLAIN_EXAMPLES are names to try before anyone has asked.
const EXPLAIN_EXAMPLES = ["doubleclick.net", "xn--pple-43d.com", "wikipedia.org"];

// VERDICTS say each decision in a word, with a symbol and a tone.
const VERDICTS = {
  allow: ["Allowed", "allow", "ok"],
  block: ["Blocked", "block", "bad"],
  rewrite: ["Answered locally", "arrow", "info"],
  refuse: ["Refused", "x", "warn"],
};

// CHECK_RESULTS say what each check did.
const CHECK_RESULTS = { pass: ["Passed", "check"], match: ["Decided", "arrow"], skip: ["Not checked", "x"] };

// explainEmpty invites a first question.
function explainEmpty() {
  return h("div", { class: "explain-empty" },
    buddy("calm"),
    h("p", {}, h("strong", { text: "Ask about any name." }), " doh shows what it would do, why, and every check on the way."),
    h("p", { class: "examples" }, h("span", { class: "muted", text: "Try " }),
      ...EXPLAIN_EXAMPLES.flatMap((d, i) => [i ? h("span", { class: "muted", text: " · " }) : null,
        h("button", { type: "button", class: "link mono", text: d, onClick: () => explainDomain(d) })])),
  );
}

// why says in a sentence why a query was decided as it was, naming the
// profile and the check that decided it.
function why(x) {
  const d = x.decision || {};
  const where = x.profile ? [" in ", h("strong", { text: profileName(x.profile) })] : [];
  switch (d.action) {
    case "block": {
      const source = d.source ? reasonText({ reason: d.reason, source: d.source }).replace(/^[^:]+: /, "") : "";
      return ["Blocked", ...where, " by ", h("strong", { text: checkName(d.reason) }), source ? ` (${source})` : "", "."];
    }
    case "rewrite": return ["Answered", ...where, " by a rewrite, with ", h("span", { class: "mono", text: x.answers?.length ? x.answers.join(", ") : "local records" }), "."];
    case "refuse": return ["No profile matches this client, so the server refuses it."];
    default: return d.reason === "allow"
      ? ["It's on the allowed list", ...where, ", so nothing blocks it."]
      : ["Nothing", ...where, " blocks it, so doh asks its upstream resolvers."];
  }
}

const profileName = (id) => { const p = state.profiles.find((x) => x.id === id); return p?.name || id; };

async function runExplain(ev) {
  ev?.preventDefault();
  const out = $("explain-result");
  const name = $("x-name").value.trim();
  if (!name) { clear(out).append(explainEmpty()); return; }
  const x = await api("GET", "/explain", {
    query: { name, type: $("x-type").value.trim() || "A", profile: $("x-profile").value, client: $("x-client").value.trim() },
  });
  const d = x.decision || {};
  const [word, sym, tone] = VERDICTS[d.action] || [d.action, "arrow", "info"];

  const facts = h("dl", { class: "facts" });
  const fact = (k, v, mono = true) => { if (v) facts.append(h("div", {}, h("dt", { text: k }), h("dd", { class: mono ? "mono" : "", text: v }))); };
  fact("Profile", x.profile && profileName(x.profile), false);
  fact("Device", x.device);
  fact("Client", x.client);
  fact("Rule", d.rule);
  fact("Response", x.rcode);

  const verdict = h("section", { class: `card verdict-card ${tone}`, "aria-labelledby": "verdict-word" },
    h("div", { class: "verdict-head" },
      h("span", { class: "verdict-icon" }, icon(sym)),
      h("div", {},
        h("p", { class: "verdict-name mono", text: `${x.name} ${x.type}` }),
        h("h3", { id: "verdict-word", class: "verdict-word", text: word }),
      ),
    ),
    h("p", { class: "verdict-why" }, ...why(x)),
    // The detail adds to the sentence, except for apps and schedules,
    // which the sentence already names.
    d.detail && d.reason !== "service" && d.reason !== "schedule" ? h("p", { class: "muted verdict-detail", text: d.detail }) : null,
    facts.childElementCount ? facts : null,
  );

  // One click to change it, with Undo on the notice that confirms it.
  const p = state.profiles.find((pp) => pp.id === x.profile);
  if (p && !state.readOnly && (d.action === "block" || d.action === "allow")) {
    const blocked = d.action === "block";
    verdict.append(h("div", { class: "actions start" }, h("button", {
      type: "button", class: blocked ? "primary" : "",
      onClick: () => changeDomain(p, x.name, blocked ? "allow" : "deny").then(() => runExplain()).catch(report),
    }, icon(blocked ? "allow" : "block"), `${blocked ? "Allow" : "Block"} it in ${p.name || p.id}`),
    h("a", { class: "button", href: routeHash("logs", "", { q: x.name }) }, icon("log"), "Find it in Activity")));
  }

  const steps = h("ol", { class: "steps-list", "aria-label": "How doh decided" },
    (x.checks || []).map((c) => {
      const [label, cicon] = CHECK_RESULTS[c.result] || [c.result, "arrow"];
      return h("li", { class: `step is-${c.result}` },
        h("span", { class: "step-dot", "aria-hidden": "true" }, icon(cicon)),
        h("div", { class: "step-body" },
          h("div", { class: "step-head" }, h("strong", { text: checkName(c.check) }), h("span", { class: "step-result", text: label })),
          c.detail ? h("p", { class: "muted", text: c.detail }) : null),
      );
    }));
  const how = h("section", { class: "card", "aria-labelledby": "how-title" }, h("h3", { id: "how-title", text: "How doh decided" }), steps);
  const answers = x.answers?.length
    ? h("section", { class: "card", "aria-labelledby": "answers-title" }, h("h3", { id: "answers-title", text: "Answers" }), x.answers.map((a) => h("div", { class: "mono answer", text: a })))
    : null;
  clear(out).append(h("div", { class: "explain-grid" }, verdict, how, answers));
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

  const summary = [count(profiles.length, "profile"), networks.length ? count(networks.length, "network") : "no networks", t.custom_lists ? "custom lists allowed" : null].filter(Boolean).join(" · ");
  const head = h("div", { class: "tenant-head" },
    badge(t.name || t.id),
    h("div", { class: "tenant-title" },
      h("h3", {}, t.name || t.id, " ", h("span", { class: "muted mono", text: t.id })),
      h("p", { class: "muted", text: summary })),
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

// renderSecurity lists who can use the admin API: people and their
// passkeys, and service accounts and their keys. The operator sees them
// grouped by tenant.
async function renderSecurity() {
  const me = state.auth?.session;
  $("add-passkey-person").hidden = !!me?.person;
  $("ap-person").required = !me?.person;

  const host = $("security-host");
  const rpID = state.auth?.rp_id;
  host.hidden = !rpID || location.hostname === rpID;
  host.textContent = host.hidden ? "" : `Passkeys for this server only work at ${rpID}. Open the UI there to add one.`;

  const [peopleData, accountData] = await Promise.all([api("GET", "/people"), api("GET", "/service-accounts")]);
  const people = peopleData?.people || [];
  renderPeople(people, me);
  renderServiceAccounts(accountData?.service_accounts || [], people);
  await renderAlerts();
}

// byTenant groups items by their tenant, the operator's first, then
// tenants by name. It returns one group when there's nothing to tell
// apart, so a tenant's own view has no group headings.
function byTenant(items) {
  const groups = new Map();
  for (const item of items) {
    const key = item.tenant || "";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  const keys = [...groups.keys()].sort((x, y) => (x === "" ? -1 : y === "" ? 1 : tenantName(x).localeCompare(tenantName(y))));
  return keys.map((k) => [k, groups.get(k)]);
}

// grouped renders items under their tenant's name, when the operator
// sees more than one tenant's.
function grouped(box, items, render) {
  const groups = byTenant(items);
  const labelled = isOperator() && groups.length > 1;
  for (const [tenant, list] of groups) {
    if (labelled) box.append(h("p", { class: "group-label", text: tenant ? tenantName(tenant) : "Operator" }));
    for (const item of list) box.append(render(item));
  }
}

function renderPeople(people, me) {
  const box = clear($("people"));
  if (!people.length) {
    box.append(h("p", { class: "muted empty", text: "No one has a passkey yet. Until someone does, sign-in links from doh ui sign in on their own." }));
    return;
  }
  grouped(box, people, (person) => {
    const mine = person.id === me?.person;
    const head = h("div", { class: "person-head" },
      badge(person.name),
      h("h4", {}, person.name, mine ? h("span", { class: "badge you", text: "You" }) : null),
      h("span", { class: "badge", text: person.role }),
      isAdmin() ? h("button", { type: "button", class: "ghost danger-text", text: "Remove", "aria-label": `Remove ${person.name}`, onClick: () => removePerson(person, mine) }) : null,
    );
    const keys = h("ul", { class: "passkeys" }, person.passkeys.map((k) => h("li", { class: "passkey" },
      h("div", { class: "passkey-name" }, k.name, k.synced ? h("span", { class: "badge synced", text: "Synced", title: "A multi-device passkey, backed up to the person's account" }) : null),
      h("div", { class: "muted passkey-meta", text: `Added ${fmtTime(k.created, true)} · ${k.last_used ? "last used " + fmtTime(k.last_used, true) : "never used"}` }),
      isAdmin() ? h("button", { type: "button", class: "ghost danger-text", text: "Remove", "aria-label": `Remove passkey ${k.name}`, onClick: () => removePasskey(person, k, mine) }) : null,
    )));
    return h("article", { class: "card person" }, head, keys);
  });
}

// ---------- service accounts ----------

// soonDays is when a key's coming expiry is worth pointing out.
const soonDays = 14;

// statusIcon marks a status with an icon from the set, sized to its text;
// the words beside it say the same, so color and shape are never alone.
const statusIcon = (name) => icon(name, "status-icon");

// keyStatus describes a key's expiry in words and a symbol, never by
// color alone.
function keyStatus(k, now = Date.now()) {
  const left = new Date(k.expires).getTime() - now;
  if (left <= 0) return h("span", { class: "status bad" }, statusIcon("block"), `Expired ${fromNow(k.expires, now)}`);
  const text = `Expires ${fromNow(k.expires, now)}`;
  if (left <= soonDays * 864e5) return h("span", { class: "status warn" }, statusIcon("warn"), text);
  return h("span", { class: "status", title: formatDate(k.expires) }, text);
}

function renderServiceAccounts(accounts, people = []) {
  const box = clear($("service-accounts"));
  $("new-sa").hidden = !isAdmin();
  if (!accounts.length) {
    box.append(h("p", { class: "muted empty", text: "None yet. Make one for each script or device that talks to this server, so each can be revoked on its own." }));
    return;
  }
  grouped(box, accounts, (a) => {
    const now = Date.now();
    const keys = [...a.keys].sort((x, y) => new Date(y.expires) - new Date(x.expires));
    const live = keys.filter((k) => new Date(k.expires).getTime() > now).length;
    const head = h("div", { class: "person-head" },
      badge(a.name, "key"),
      h("h4", {}, a.name),
      h("span", { class: "badge", text: a.role }),
      isAdmin() ? h("button", { type: "button", class: "ghost", text: "Add key", "aria-label": `Add a key to ${a.name}`, onClick: () => addKey(a) }) : null,
      isAdmin() ? h("button", { type: "button", class: "ghost danger-text", text: "Delete", "aria-label": `Delete ${a.name}`, onClick: () => deleteAccount(a) }) : null,
    );
    const meta = h("p", { class: "muted passkey-meta account-meta" },
      h("code", { text: a.id, title: "Service account ID" }),
      ` · made ${fromNow(a.created)}${a.created_by ? " by " + describeActor(a.created_by, people) : ""}`,
      live ? "" : " · no working key");
    const list = keys.length
      ? h("ul", { class: "passkeys" }, keys.map((k) => {
        const expired = new Date(k.expires).getTime() <= now;
        return h("li", { class: "passkey" + (expired ? " expired" : "") },
          h("div", { class: "passkey-name" }, h("code", { text: k.id, title: "Key ID: the start of its secret, after doh_sa_" })),
          h("div", { class: "muted passkey-meta" }, keyStatus(k, now), ` · ${k.last_used ? "used " + fromNow(k.last_used) : "never used"}`),
          isAdmin() ? h("div", { class: "row-actions" },
            expired ? null : h("button", { type: "button", class: "ghost", text: "Rotate", "aria-label": `Rotate key ${k.id}`, onClick: () => rotateKey(a, k) }),
            h("button", { type: "button", class: "ghost danger-text", text: expired ? "Remove" : "Revoke", "aria-label": `${expired ? "Remove" : "Revoke"} key ${k.id}`, onClick: () => revokeKey(a, k, expired) }),
          ) : null,
        );
      }))
      : null;
    return h("article", { class: "card person" }, head, meta, list);
  });
}

// describeActor names who made something, from the server's record of
// it: a person by name, or how someone signed in.
function describeActor(by, people) {
  const person = people.find((p) => p.id === by);
  if (person) return person.name;
  return { "admin token": "the admin token", "reader token": "the reader token", "sign-in link": "a sign-in link" }[by] || "someone no longer here";
}

function openCreateAccount() {
  $("sa-name").value = "";
  $("sa-form").querySelector('input[value="reader"]').checked = true;
  $("sa-expires").value = "90";
  const sel = $("sa-tenant");
  sel.replaceChildren(sel.options[0]);
  for (const t of state.tenants) sel.append(h("option", { value: t.id, text: t.name || t.id }));
  $("sa-tenant-row").hidden = !isOperator() || !state.tenants.length;
  $("sa-dialog").showModal();
}

async function createAccount(e) {
  e.preventDefault();
  const form = $("sa-form");
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    const body = {
      name: $("sa-name").value.trim(),
      role: form.querySelector('input[name="sa-role"]:checked').value,
    };
    if (isOperator() && $("sa-tenant").value) body.tenant = $("sa-tenant").value;
    const account = await api("POST", "/service-accounts", { body });
    const key = await api("POST", `/service-accounts/${encodeURIComponent(account.id)}/keys`, { body: { expires: daysFromNow($("sa-expires").value) } });
    $("sa-dialog").close();
    await renderSecurity();
    revealSecret(account, key);
  } catch (err) {
    report(err);
  } finally {
    submit.disabled = false;
  }
}

// daysFromNow returns the time n days from now, as the API takes it.
const daysFromNow = (n) => new Date(Date.now() + Number(n) * 864e5).toISOString();

async function addKey(a) {
  try {
    const key = await api("POST", `/service-accounts/${encodeURIComponent(a.id)}/keys`, { body: { expires: daysFromNow(90) } });
    await renderSecurity();
    revealSecret(a, key);
  } catch (err) {
    report(err);
  }
}

// rotating is the key the rotate dialog is for.
let rotating = null;

function rotateKey(a, k) {
  rotating = { a, k };
  $("rotate-title").textContent = `Rotate key ${k.id}`;
  $("rotate-grace").value = "3600";
  $("rotate-expires").value = "90";
  $("rotate-dialog").showModal();
}

async function submitRotate(e) {
  e.preventDefault();
  if (!rotating) return;
  const { a, k } = rotating;
  const grace = Number($("rotate-grace").value);
  const body = { expires: daysFromNow($("rotate-expires").value) };
  if (grace) body.previous_expires = new Date(Date.now() + grace * 1000).toISOString();
  try {
    const key = await api("POST", `/service-accounts/${encodeURIComponent(a.id)}/keys/${encodeURIComponent(k.id)}/rotate`, { body });
    $("rotate-dialog").close();
    rotating = null;
    await renderSecurity();
    revealSecret(a, key, grace ? `Key ${k.id} keeps working ${fromNow(body.previous_expires)}.` : `Key ${k.id} no longer works.`);
  } catch (err) {
    report(err);
  }
}

async function revokeKey(a, k, expired) {
  if (!expired && !(await confirmDialog(`Revoke key ${k.id}?`, `Anything using it to reach this server as ${a.name} stops working at once.`, "Revoke"))) return;
  try {
    await api("DELETE", `/service-accounts/${encodeURIComponent(a.id)}/keys/${encodeURIComponent(k.id)}`);
    toast(expired ? `Removed expired key ${k.id}.` : `Revoked key ${k.id}.`);
    await renderSecurity();
  } catch (err) {
    report(err);
  }
}

async function deleteAccount(a) {
  const keys = a.keys.length === 1 ? "Its key stops" : a.keys.length ? `Its ${a.keys.length} keys stop` : "Nothing uses it yet, so nothing stops";
  if (!(await confirmDialog(`Delete ${a.name}?`, `${keys} working at once.`))) return;
  try {
    await api("DELETE", `/service-accounts/${encodeURIComponent(a.id)}`);
    toast(`Deleted ${a.name}.`);
    await renderSecurity();
  } catch (err) {
    report(err);
  }
}

// revealSecret shows a new key's secret, once. It's cleared from the page
// when the dialog closes, and Done waits until it's saved.
function revealSecret(account, key, note = "") {
  showSecret(`New key for ${account.name}`, key.secret,
    [note, `It expires ${formatDate(key.key.expires)}. Send it as a bearer token, or to doh as DOH_TOKEN.`].filter(Boolean).join(" "));
}

// showSecret shows a secret the server returns only once.
function showSecret(title, secret, meta) {
  const dlg = $("secret-dialog");
  $("secret-title").textContent = title;
  $("secret-value").textContent = secret;
  $("secret-meta").textContent = meta;
  $("secret-saved").checked = false;
  $("secret-done").disabled = true;
  $("secret-copy").textContent = "Copy";
  dlg.addEventListener("close", () => { $("secret-value").textContent = ""; }, { once: true });
  dlg.showModal();
  $("secret-copy").focus();
}

async function copySecret() {
  const button = $("secret-copy");
  try {
    await navigator.clipboard.writeText($("secret-value").textContent);
    button.textContent = "Copied ✓";
    setTimeout(() => { button.textContent = "Copy"; }, 2000);
  } catch {
    // Without clipboard access, select it for copying by hand.
    const range = document.createRange();
    range.selectNodeContents($("secret-value"));
    getSelection().removeAllRanges();
    getSelection().addRange(range);
    toast("Select and copy the key by hand.");
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

// ---------- alerts ----------

// ALERT_KINDS says what each kind of alert is about, in a person's words.
const ALERT_KINDS = {
  threat: ["Threats blocked", "A device tried to reach a phishing, malware, or tunneling domain. Sent even in quiet hours."],
  "new-device": ["New devices", "Something new started using this server, after an hour of getting to know the network."],
  failing: ["Lookups failing", "Many queries are failing, so sites may not load."],
  "list-failed": ["Lists that didn't load", "A blocklist couldn't be fetched or read, so it's out of date."],
};

// alertsTenant is whose alerts the operator is looking at: "" for their
// own.
let alertsTenant = "";

const alertsQuery = () => (isOperator() && alertsTenant ? { tenant: alertsTenant } : undefined);

// renderAlerts shows alert settings, destinations, and recent deliveries,
// to admins: destinations' URLs can be enough to read the alerts.
async function renderAlerts() {
  const section = $("alerts-section");
  section.hidden = !isAdmin();
  if (section.hidden) return;
  let data;
  try {
    data = await api("GET", "/alerts", { query: alertsQuery() });
  } catch (err) {
    if (err instanceof APIError && err.status === 403) { section.hidden = true; return; }
    throw err;
  }
  const box = clear($("alerts"));
  $("alerts-test").disabled = !data.destinations.length;

  if (isOperator() && state.tenants.length) {
    const pick = h("select", { "aria-label": "Whose alerts" },
      h("option", { value: "", text: "Yours, as the operator" }),
      state.tenants.map((t) => h("option", { value: t.id, text: t.name || t.id })));
    pick.value = alertsTenant;
    pick.addEventListener("change", () => { alertsTenant = pick.value; renderAlerts().catch(report); });
    box.append(h("label", { class: "alerts-for" }, "Alerts for ", pick));
  }

  // What to hear about.
  const kinds = h("div", { class: "toggle-list" });
  for (const kind of data.available_kinds) {
    const [title, desc] = ALERT_KINDS[kind] || [kind, ""];
    const input = h("input", { type: "checkbox", role: "switch", checked: data.settings.kinds.includes(kind), "aria-label": title });
    input.addEventListener("change", () => {
      const on = new Set(data.settings.kinds);
      if (input.checked) on.add(kind); else on.delete(kind);
      saveAlertSettings({ kinds: data.available_kinds.filter((k) => on.has(k)) }, input.checked ? `${title}: on` : `${title}: off`, input);
    });
    kinds.append(h("div", { class: "toggle" }, h("div", { class: "title", text: title }), h("div", { class: "control" }, input), h("div", { class: "desc", text: desc })));
  }
  box.append(h("div", { class: "section" }, h("h4", { text: "What to hear about" }), kinds));

  box.append(quietHours(data.settings));
  box.append(destinationsList(data.destinations));

  if (data.deliveries.length) {
    box.append(h("div", { class: "section" }, h("h4", { text: "Recently sent" }),
      h("ul", { class: "deliveries" }, data.deliveries.slice(0, 5).map((d) => h("li", {},
        deliveryStatus(d),
        h("div", {},
          h("div", { class: "delivery-summary", text: d.summary }),
          h("div", { class: "muted", text: `To ${destinationName(data.destinations, d.destination)} · ${fromNow(d.time)}${d.ok ? "" : " · " + (d.error || "failed")}` })),
      )))));
  }
}

// destinationName names a destination by its ID, for deliveries.
function destinationName(destinations, id) {
  const d = destinations.find((x) => x.id === id);
  return d ? d.name || d.url : "a removed destination";
}

// deliveryStatus says how a delivery went, by symbol and word as well as
// color.
function deliveryStatus(d) {
  return d.ok
    ? h("span", { class: "status ok", title: "Delivered" }, statusIcon("check"), h("span", { class: "visually-hidden", text: "Delivered: " }))
    : h("span", { class: "status bad", title: d.error || "Failed" }, statusIcon("block"), h("span", { class: "visually-hidden", text: "Failed: " }));
}

// quietHours edits the daily period when only threats are sent.
function quietHours(settings) {
  const q = settings.quiet_hours;
  const zone = settings.time_zone || Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  const toggle = h("input", { type: "checkbox", role: "switch", checked: !!q, "aria-label": "Quiet hours" });
  const start = h("input", { type: "time", value: q?.start || "22:00", "aria-label": "Quiet hours start" });
  const end = h("input", { type: "time", value: q?.end || "07:00", "aria-label": "Quiet hours end" });
  const times = h("div", { class: "quiet-times" }, start, h("span", { class: "muted", text: "to" }), end,
    h("span", { class: "muted", text: zone.replaceAll("_", " ") }));
  times.hidden = !q;
  const save = (msg) => saveAlertSettings(
    toggle.checked ? { quiet_hours: { start: start.value, end: end.value }, time_zone: zone } : { quiet_hours: null },
    msg, toggle);
  toggle.addEventListener("change", () => { times.hidden = !toggle.checked; save(toggle.checked ? `Quiet hours: ${start.value} to ${end.value}` : "Quiet hours: off"); });
  for (const input of [start, end]) input.addEventListener("change", () => { if (start.value && end.value) save(`Quiet hours: ${start.value} to ${end.value}`); });
  return h("div", { class: "section" }, h("h4", { text: "When" }),
    h("div", { class: "toggle" },
      h("div", { class: "title", text: "Quiet hours" }),
      h("div", { class: "control" }, toggle),
      h("div", { class: "desc", text: "Only threats come through, and the rest wait until it's over, summed up." })),
    times);
}

async function saveAlertSettings(patch, message, input) {
  if (input) input.disabled = true;
  try {
    await api("PATCH", "/alerts", { body: patch, patch: true, query: alertsQuery() });
    toast(message);
  } catch (err) {
    report(err);
  }
  await renderAlerts().catch(report);
}

// destinationsList lists where alerts go, and how each last went.
function destinationsList(destinations) {
  const body = destinations.length
    ? h("ul", { class: "passkeys" }, destinations.map((d) => {
      const failedLast = d.last_failure && (!d.last_success || new Date(d.last_failure) > new Date(d.last_success));
      const health = failedLast
        ? h("span", { class: "status bad" }, statusIcon("block"), `Failed ${fromNow(d.last_failure)}`)
        : d.last_success
          ? h("span", { class: "status ok" }, statusIcon("check"), `Delivered ${fromNow(d.last_success)}`)
          : h("span", { class: "status", text: "Nothing sent yet" });
      return h("li", { class: "passkey" },
        h("div", { class: "passkey-name" }, d.name || d.url, h("span", { class: "badge", text: d.type === "ntfy" ? "ntfy" : "Webhook" })),
        d.name ? h("code", { class: "passkey-meta dest-url", text: d.url }) : null,
        h("div", { class: "passkey-meta" }, health),
        failedLast && d.last_error ? h("div", { class: "passkey-meta dest-error", text: d.last_error }) : null,
        h("button", { type: "button", class: "ghost danger-text", text: "Remove", "aria-label": `Remove ${d.name || d.url}`, onClick: () => removeDestination(d) }),
      );
    }))
    : h("p", { class: "muted empty" }, "Nowhere yet. ",
      h("button", { type: "button", class: "link", text: "Add ntfy", onClick: () => openAddDestination("ntfy") }),
      " to get alerts on your phone in a minute.");
  return h("div", { class: "section" }, h("h4", { text: "Where they go" }), body);
}

// NTFY is ntfy's public server, suggested for new destinations; the page
// never fetches it.
const NTFY = "https://ntfy.sh/";

// ntfyTopic suggests a topic no one will guess: on ntfy, knowing a topic
// is all it takes to read it.
function ntfyTopic() {
  const bytes = crypto.getRandomValues(new Uint8Array(9));
  const alphabet = "abcdefghijkmnpqrstuvwxyz23456789";
  return NTFY + "doh-" + [...bytes].map((b) => alphabet[b % alphabet.length]).join("");
}

function alertTypeChanged() {
  const type = $("alert-form").querySelector('input[name="alert-type"]:checked').value;
  const url = $("alert-url");
  if (type === "ntfy") {
    if (!url.value || !url.value.startsWith(NTFY)) url.value = ntfyTopic();
    url.placeholder = NTFY + "your-topic";
    $("alert-url-hint").textContent = "Subscribe to this topic in the ntfy app. Anyone who knows the topic can read what's sent to it, so keep it hard to guess. Your own ntfy server works too.";
  } else {
    if (url.value.startsWith(NTFY)) url.value = "";
    url.placeholder = "https://example.com/hooks/doh";
    $("alert-url-hint").textContent = "An https URL. Each delivery is signed as Standard Webhooks describes, with a secret shown once you add it.";
  }
}

function openAddDestination(type = "ntfy") {
  const form = $("alert-form");
  form.reset();
  form.querySelector(`input[name="alert-type"][value="${type}"]`).checked = true;
  $("alert-url").value = "";
  alertTypeChanged();
  $("alert-dialog").showModal();
  $("alert-name").focus();
}

async function addDestination(e) {
  e.preventDefault();
  const form = $("alert-form");
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    const body = {
      type: form.querySelector('input[name="alert-type"]:checked').value,
      url: $("alert-url").value.trim(),
      name: $("alert-name").value.trim(),
    };
    const created = await api("POST", "/alerts/destinations", { body, query: alertsQuery() });
    $("alert-dialog").close();
    await renderAlerts();
    const name = created.destination.name || created.destination.url;
    if (created.secret) {
      showSecret(`Signing secret for ${name}`, created.secret,
        "Check each delivery's webhook-signature header with it, so you know it came from this server.");
    } else {
      toast(`Added ${name}. Send a test to check it.`);
    }
  } catch (err) {
    report(err);
  } finally {
    submit.disabled = false;
  }
}

async function removeDestination(d) {
  const name = d.name || d.url;
  if (!(await confirmDialog(`Remove ${name}?`, "Alerts stop going there at once.", "Remove"))) return;
  try {
    await api("DELETE", `/alerts/destinations/${encodeURIComponent(d.id)}`, { query: alertsQuery() });
    toast(`Removed ${name}.`);
    await renderAlerts();
  } catch (err) {
    report(err);
  }
}

async function testAlerts() {
  const button = $("alerts-test");
  button.disabled = true;
  button.textContent = "Sending…";
  try {
    const result = await api("POST", "/alerts/test", { query: alertsQuery() });
    const failed = result.deliveries.filter((d) => !d.ok);
    if (!failed.length) toast(result.deliveries.length === 1 ? "Sent. Check that it arrived." : `Sent to all ${result.deliveries.length}. Check that they arrived.`);
    else toast(`Couldn't reach ${failed.map((d) => d.destination).join(", ")}: ${failed[0].error || "it failed"}`, { error: true });
  } catch (err) {
    report(err);
  } finally {
    button.textContent = "Send a test";
    await renderAlerts().catch(report);
  }
}

// ---------- theme ----------

function wireTheme() {
  const sync = () => {
    const t = currentTheme();
    const icon = { system: "i-system", light: "i-sun", dark: "i-moon" }[t];
    for (const b of document.querySelectorAll("[data-theme-toggle]")) {
      b.setAttribute("aria-label", `Theme: ${themeLabel(t)}. Change it`);
      b.title = `Theme: ${themeLabel(t)}`;
      b.querySelector("use").setAttribute("href", "#" + icon);
      const label = b.querySelector("[data-theme-label]");
      if (label) label.textContent = `Theme: ${themeLabel(t)}`;
    }
  };
  for (const b of document.querySelectorAll("[data-theme-toggle]")) {
    b.addEventListener("click", () => { cycleTheme(); sync(); });
  }
  sync();
  wireTheme.sync = sync;
}

function cycleTheme() {
  const t = nextTheme(currentTheme());
  applyTheme(t);
  wireTheme.sync?.();
  toast(`Theme: ${themeLabel(t)}`);
}

// ---------- command palette ----------

let palette;

// commands returns what the palette offers for query: places, profiles,
// actions, and, for anything that looks like a domain, what can be done
// with it.
function commands(query) {
  const list = [];
  const goTo = (view, title, icon, keywords = []) => ({ id: "go-" + view, group: "Go to", title, icon, keywords, run: () => go(view) });
  list.push(
    goTo("overview", "Overview", "i-overview", ["home", "dashboard", "stats"]),
    goTo("profiles", "Profiles", "i-profiles", ["devices", "rules", "settings"]),
    goTo("logs", "Activity", "i-log", ["query log", "logs", "queries", "history"]),
    goTo("explain", "Explain a query", "i-explain", ["why", "debug", "test"]),
    goTo("security", "Security", "i-security", ["passkeys", "people", "service accounts", "keys", "tokens", "alerts", "notifications", "ntfy", "webhooks"]),
  );
  if (isOperator()) list.push(goTo("tenants", "Tenants", "i-tenants", ["households", "customers", "organizations"]));

  for (const p of state.profiles) {
    list.push({ id: "profile-" + p.id, group: "Profiles", title: p.name || p.id, hint: p.name ? p.id : "", icon: "i-profiles", keywords: [p.id, "profile"], run: () => go("profiles", p.id) });
  }

  const d = query.trim().toLowerCase().replace(/\.$/, "");
  if (looksLikeDomain(d)) {
    const group = d;
    list.unshift(
      { id: "explain-d", group, title: `Explain ${d}`, icon: "i-explain", run: () => explainDomain(d) },
      { id: "find-d", group, title: `Find ${d} in activity`, icon: "i-log", run: () => findInActivity(d) },
    );
    if (!state.readOnly) {
      const targets = state.profiles.slice(0, 6);
      list.splice(2, 0,
        ...targets.map((p) => ({ id: "block-" + p.id, group, title: `Block ${d} in ${p.name || p.id}`, icon: "i-block", run: () => changeDomain(p, d, "deny") })),
        ...targets.map((p) => ({ id: "allow-" + p.id, group, title: `Allow ${d} in ${p.name || p.id}`, icon: "i-allow", run: () => changeDomain(p, d, "allow") })),
      );
    }
  }

  if (isAdmin()) {
    list.push(
      { id: "new-profile", group: "Actions", title: "New profile", icon: "i-plus", keywords: ["create", "add"], run: () => { go("profiles"); openCreate(); } },
      { id: "new-sa", group: "Actions", title: "New service account", icon: "i-key", keywords: ["create", "token", "api key", "automation"], run: () => { go("security"); openCreateAccount(); } },
    );
    if (isOperator()) list.push({ id: "new-tenant", group: "Actions", title: "New tenant", icon: "i-tenants", keywords: ["create", "household"], run: () => { go("tenants"); openCreateTenant(); } });
  }
  list.push(
    { id: "theme", group: "Preferences", title: `Change the theme (now ${themeLabel(currentTheme()).toLowerCase()})`, icon: "i-sun", keywords: ["dark", "light", "appearance"], run: cycleTheme },
    { id: "shortcuts", group: "Help", title: "Keyboard shortcuts", icon: "i-keyboard", keywords: ["keys", "help"], run: () => $("shortcuts").showModal() },
    { id: "signout", group: "Account", title: "Sign out", icon: "i-signout", hidden: true, run: signOut },
  );
  return list;
}

function paletteItem(c) {
  return h("li", { class: "palette-item" },
    icon((c.icon || "i-arrow").replace(/^i-/, "")),
    h("span", { class: "palette-title", text: c.title }),
    c.hint ? h("span", { class: "palette-hint mono", text: c.hint }) : null,
    icon("arrow", "palette-go"));
}

function wirePalette() {
  palette = new Palette($("palette"), commands, paletteItem);
  $("palette").addEventListener("palette-error", (e) => report(e.detail));
  for (const b of document.querySelectorAll("[data-palette]")) b.addEventListener("click", () => palette.open());
  // Show the shortcut the way this platform writes it.
  const mac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  for (const k of document.querySelectorAll("[data-mod-key]")) k.textContent = mac ? "⌘K" : "Ctrl K";
}

async function explainDomain(d) {
  $("x-name").value = d;
  $("x-type").value = "A";
  go("explain");
  await runExplain();
}

function findInActivity(d) {
  go("logs", "", { q: d });
}

// changeDomain allows or blocks d in profile p at once, offering to undo.
async function changeDomain(p, d, list) {
  const name = p.name || p.id;
  const path = `/profiles/${encodeURIComponent(p.id)}/${list}`;
  const updated = await api("POST", path, { body: { domain: d } });
  replaceProfile(updated);
  if (state.view === "profiles") renderProfiles();
  toast(`${list === "deny" ? "Blocked" : "Allowed"} ${d} in ${name}.`, {
    action: {
      label: "Undo",
      run: async () => {
        replaceProfile(await api("DELETE", `${path}/${encodeURIComponent(d)}`));
        if (state.view === "profiles") renderProfiles();
        toast(`Undone: ${d} is back as it was in ${name}.`);
      },
    },
  });
}

// ---------- keyboard shortcuts ----------

// typing reports whether a key event is someone typing, which shortcuts
// leave alone.
const typing = (e) => e.target instanceof Element && (e.target.closest("input, textarea, select, [contenteditable]") !== null);

function wireShortcuts() {
  let pendingG = 0;
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && !e.altKey && e.key.toLowerCase() === "k") {
      if ($("app").hidden) return;
      e.preventDefault();
      palette.open();
      return;
    }
    if (e.metaKey || e.ctrlKey || e.altKey || typing(e) || $("app").hidden || document.querySelector("dialog[open]")) return;

    if (pendingG && Date.now() - pendingG < 1200) {
      pendingG = 0;
      const view = { o: "overview", p: "profiles", a: "logs", l: "logs", e: "explain", s: "security", t: "tenants" }[e.key];
      if (view) { e.preventDefault(); go(view); }
      return;
    }
    switch (e.key) {
      case "g": pendingG = Date.now(); break;
      case "?": e.preventDefault(); $("shortcuts").showModal(); break;
      case "t": e.preventDefault(); cycleTheme(); break;
      case "/":
        e.preventDefault();
        if (state.view === "logs") $("f-q").focus();
        else palette.open();
        break;
    }
  });
}

// ---------- wiring ----------

function wire() {
  $("new-sa").addEventListener("click", openCreateAccount);
  $("sa-form").addEventListener("submit", createAccount);
  $("sa-cancel").addEventListener("click", () => $("sa-dialog").close());
  $("rotate-form").addEventListener("submit", submitRotate);
  $("rotate-cancel").addEventListener("click", () => $("rotate-dialog").close());
  $("secret-copy").addEventListener("click", copySecret);
  $("alerts-add").addEventListener("click", () => openAddDestination());
  $("alerts-test").addEventListener("click", testAlerts);
  $("alert-form").addEventListener("submit", addDestination);
  $("alert-cancel").addEventListener("click", () => $("alert-dialog").close());
  for (const r of $("alert-form").querySelectorAll('input[name="alert-type"]')) r.addEventListener("change", alertTypeChanged);
  $("secret-saved").addEventListener("change", (e) => { $("secret-done").disabled = !e.target.checked; });
  $("signin-passkey").addEventListener("click", signInWithPasskey);
  $("signout").addEventListener("click", signOut);
  $("signout-mobile").addEventListener("click", () => { $("account-menu").hidePopover?.(); signOut(); });
  $("add-passkey").addEventListener("submit", addPasskey);
  wireTheme();
  wirePalette();
  wireShortcuts();
  // The top bar gains a border once the page scrolls under it.
  const bar = document.querySelector(".mobilebar");
  addEventListener("scroll", () => bar.classList.toggle("scrolled", scrollY > 4), { passive: true });
  $("new-profile").addEventListener("click", openCreate);
  $("new-tenant").addEventListener("click", openCreateTenant);
  $("tenant-form").addEventListener("submit", createTenant);
  $("tenant-cancel").addEventListener("click", () => $("tenant-dialog").close());
  $("create-form").addEventListener("submit", createProfile);
  $("create-cancel").addEventListener("click", () => $("create-dialog").close());
  $("log-filters").addEventListener("submit", (e) => { e.preventDefault(); applyLogFilter(); });
  // Choices apply at once; typing applies after a pause, or on Enter.
  for (const el of document.querySelectorAll('input[name="f-status"], #f-profile')) el.addEventListener("change", applyLogFilter);
  let typingTimer;
  for (const id of ["f-q", "f-client"]) {
    $(id).addEventListener("input", () => { clearTimeout(typingTimer); typingTimer = setTimeout(applyLogFilter, 350); });
  }
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
    else if (!$("app").hidden) applyRoute();
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("drawer").hidden) closeDrawer(); });
}

wire();
start();
