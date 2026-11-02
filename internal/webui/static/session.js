import { closeDrawer, stopLive } from "./activity.js";
import { api, APIError, authCall, report } from "./api.js";
import { $, clear, h, icon } from "./dom.js";
import { loadSetup } from "./onboarding.js";
import { renderProfiles } from "./profiles.js";
import { applyRoute } from "./router.js";
import { isFirstRun } from "./setup.js";
import { isAdmin, isOperator, state, tenantName } from "./state.js";
import { webauthnJSON } from "./webauthn.js";
import { readPrefs } from "./prefs.js";

// takeLinkCode removes a sign-in link's code from the address bar, so it
// isn't left in history or shared by accident, and returns it.
export function takeLinkCode() {
  const m = location.hash.match(/(?:^#|&)signin=([A-Za-z0-9_-]+)/);
  if (!m) return "";
  history.replaceState(null, "", location.pathname + location.search);
  return m[1];
}

// start signs in with a link in the address bar, if there is one, and
// shows the app or the sign-in screen.
export async function start() {
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
export async function route(status) {
  state.auth = status;
  if (status.signed_in) {
    await enterApp();
  } else if (status.session?.pending && status.session.method === "link") {
    showSignIn("", { pending: true });
  } else {
    showSignIn();
  }
}

export function showSignIn(message = "", { pending = false } = {}) {
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
export async function signInWithPasskey() {
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
export function passkeyError(err) {
  switch (err?.name) {
    case "NotAllowedError": return "The passkey request was cancelled or timed out.";
    case "InvalidStateError": return "This authenticator already has a passkey for this server.";
    case "SecurityError": return `Passkeys only work at ${state.auth?.rp_id || "this server's host name"}.`;
    case "NotSupportedError": return "This browser or device doesn't support passkeys.";
    default: return err?.message || "Something went wrong.";
  }
}

export async function signOut() {
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
export async function refreshAuth() {
  state.auth = await authCall("GET", "/session");
  renderWho();
}

// renderWho shows who's signed in, and recommends a passkey after a link
// sign-in while no one has one.
export function renderWho() {
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
  // The setup checklist asks for a passkey itself, while it shows.
  const checklist = isAdmin() && state.setup && !state.setup.complete && !readPrefs().setupDismissed;
  $("passkey-banner").hidden = !(s && !s.person && !state.auth.passkeys_required) || checklist;
}

export async function enterApp() {
  const [status, catalog] = await Promise.all([api("GET", "/status"), api("GET", "/catalog")]);
  state.status = status;
  state.catalog = { features: [], presets: [], services: [], ...catalog };
  setReadOnly(status.policy);
  await Promise.all([loadPolicy(), loadTenants()]);
  // Only the operator manages tenants and sees how the server runs.
  $("settings-nav-tenants").hidden = !isOperator();
  $("list-health-card").hidden = !isOperator();
  renderWho();
  // A brand-new server opens on setup, not an empty Overview.
  const setup = await loadSetup().catch(() => null);
  const landing = !location.hash;
  if (landing && setup && isFirstRun({ admin: isAdmin(), passkeysRequired: !!state.auth?.passkeys_required, profiles: state.profiles, devices: setup.devices })) {
    history.replaceState(null, "", "#/setup");
  }
  $("signin").hidden = true;
  $("app").hidden = false;
  applyRoute();
}

export function setReadOnly(policy) {
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
export async function loadTenants() {
  const data = await api("GET", "/tenants");
  state.tenants = data?.tenants || [];
}

export async function loadPolicy() {
  const data = await api("GET", "/profiles");
  state.profiles = data?.profiles || [];
  if (!state.profiles.some((p) => p.id === state.selected)) state.selected = "";
  fillProfileSelects();
  if (state.view === "profiles") renderProfiles();
}

// reload, and links work. Sign-in links use #signin=..., handled apart.

export function fillProfileSelects() {
  for (const id of ["f-profile", "x-profile"]) {
    const sel = $(id);
    const keep = sel.value;
    const first = sel.options[0];
    sel.replaceChildren(first);
    for (const p of state.profiles) sel.append(h("option", { value: p.id, text: p.name ? `${p.name} (${p.id})` : p.id }));
    sel.value = state.profiles.some((p) => p.id === keep) ? keep : "";
  }
}

