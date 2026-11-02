import { openCreateAccount } from "./accounts.js";
import { openAddDestination } from "./alerts.js";
import { report } from "./api.js";
import { $, h, icon, toast } from "./dom.js";
import { changeDomain, explainDomain, findInActivity } from "./explain.js";
import { looksLikeDomain, Palette } from "./palette.js";
import { openCreate } from "./profiles.js";
import { go } from "./router.js";
import { PROFILE_SECTIONS, settingsFor } from "./routes.js";
import { signOut } from "./session.js";
import { isAdmin, isOperator, state } from "./state.js";
import { openCreateTenant } from "./tenants.js";
import { applyTheme, currentTheme, nextTheme, themeLabel } from "./theme.js";

// syncTheme shows the current theme on every control that changes it.
export function syncTheme() {
  const t = currentTheme();
  const symbol = { system: "i-system", light: "i-sun", dark: "i-moon" }[t];
  for (const b of document.querySelectorAll("[data-theme-toggle]")) {
    b.setAttribute("aria-label", `Theme: ${themeLabel(t)}. Change it`);
    b.title = `Theme: ${themeLabel(t)}`;
    b.querySelector("use").setAttribute("href", "#" + symbol);
    const label = b.querySelector("[data-theme-label]");
    if (label) label.textContent = `Theme: ${themeLabel(t)}`;
  }
  for (const r of document.querySelectorAll('input[name="theme-choice"]')) r.checked = r.value === t;
}

export function wireTheme() {
  for (const b of document.querySelectorAll("[data-theme-toggle]")) b.addEventListener("click", cycleTheme);
  syncTheme();
}

export function cycleTheme() {
  const t = nextTheme(currentTheme());
  applyTheme(t);
  syncTheme();
  toast(`Theme: ${themeLabel(t)}`);
}

export let palette;

// commands returns what the palette offers for query: places, profiles
// and their sections, actions, and, for anything that looks like a
// domain, what can be done with it. Everything in the UI is reachable
// from here.
export function commands(query) {
  const list = [];
  const place = (id, title, icon, route, keywords = []) => ({ id: "go-" + id, group: "Go to", title, icon, keywords, run: () => go(...route) });
  list.push(
    place("overview", "Overview", "i-overview", ["overview"], ["home", "dashboard", "stats", "today"]),
    place("profiles", "Profiles", "i-profiles", ["profiles"], ["devices", "rules"]),
    place("logs", "Activity", "i-log", ["logs"], ["query log", "logs", "queries", "history"]),
    place("explain", "Explain a query", "i-explain", ["explain"], ["why", "debug", "test"]),
    place("setup", "Setup guide", "i-sparkle", ["setup"], ["onboarding", "getting started", "checklist", "router", "network", "dhcp"]),
  );
  for (const s of settingsFor({ operator: isOperator(), admin: isAdmin() })) {
    list.push(place("settings-" + s.id, `Settings: ${s.title}`, "i-" + s.icon, ["settings", s.id], {
      account: ["passkeys", "sign out", "theme", "appearance", "me"],
      people: ["invite", "household", "family", "users"],
      alerts: ["notifications", "push", "email", "ntfy", "webhooks", "quiet hours"],
      api: ["service accounts", "keys", "tokens", "automation", "home assistant"],
      tenants: ["households", "customers", "organizations"],
      server: ["version", "upstreams", "blocklists", "lists", "status"],
      audit: ["audit", "activity log", "who changed", "changes", "history"],
    }[s.id] || []));
  }

  for (const p of state.profiles) {
    const name = p.name || p.id;
    list.push({ id: "profile-" + p.id, group: "Profiles", title: name, hint: p.name ? p.id : "", icon: "i-profiles", keywords: [p.id, "profile"], run: () => go("profiles", p.id) });
    for (const t of PROFILE_SECTIONS) {
      list.push({ id: `profile-${p.id}-${t.id}`, group: "Profiles", title: `${name}: ${t.title}`, icon: "i-" + t.icon, hidden: true, keywords: [p.id], run: () => go("profiles", p.id, { tab: t.id }) });
    }
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
    const first = state.profiles.find((p) => p.id !== "default") || state.profiles[0];
    list.push(
      first ? { id: "connect", group: "Actions", title: "Connect a device", icon: "i-phone", keywords: ["setup link", "qr", "phone", "tablet", "add device"], run: () => go("profiles", first.id, { tab: "connect" }) } : null,
      { id: "new-profile", group: "Actions", title: "New profile", icon: "i-plus", keywords: ["create", "add"], run: () => { go("profiles"); openCreate(); } },
      { id: "invite", group: "Actions", title: "Invite someone", icon: "i-people", keywords: ["person", "sign-in link", "household"], run: () => go("settings", "people") },
      { id: "add-alert", group: "Actions", title: "Add an alert destination", icon: "i-bell", keywords: ["ntfy", "webhook", "email", "push", "notifications"], run: () => { go("settings", "alerts"); openAddDestination(); } },
      { id: "new-sa", group: "Actions", title: "New service account", icon: "i-key", keywords: ["create", "token", "api key", "automation"], run: () => { go("settings", "api"); openCreateAccount(); } },
    );
    if (isOperator()) list.push({ id: "new-tenant", group: "Actions", title: "New tenant", icon: "i-tenants", keywords: ["create", "household"], run: () => { go("settings", "tenants"); openCreateTenant(); } });
  }
  list.push(
    { id: "add-passkey", group: "Actions", title: "Add a passkey", icon: "i-key", keywords: ["face id", "touch id", "security key", "sign in"], run: () => go("settings", "account") },
    { id: "theme", group: "Preferences", title: `Change the theme (now ${themeLabel(currentTheme()).toLowerCase()})`, icon: "i-sun", keywords: ["dark", "light", "appearance"], run: cycleTheme },
    { id: "shortcuts", group: "Help", title: "Keyboard shortcuts", icon: "i-keyboard", keywords: ["keys", "help"], run: () => $("shortcuts").showModal() },
    { id: "signout", group: "Account", title: "Sign out", icon: "i-signout", hidden: true, run: signOut },
  );
  return list.filter(Boolean);
}

export function paletteItem(c) {
  return h("li", { class: "palette-item" },
    icon((c.icon || "i-arrow").replace(/^i-/, "")),
    h("span", { class: "palette-title", text: c.title }),
    c.hint ? h("span", { class: "palette-hint mono", text: c.hint }) : null,
    icon("arrow", "palette-go"));
}

export function wirePalette() {
  palette = new Palette($("palette"), commands, paletteItem);
  $("palette").addEventListener("palette-error", (e) => report(e.detail));
  for (const b of document.querySelectorAll("[data-palette]")) b.addEventListener("click", () => palette.open());
  // Show the shortcut the way this platform writes it.
  const mac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  for (const k of document.querySelectorAll("[data-mod-key]")) k.textContent = mac ? "⌘K" : "Ctrl K";
}

// typing reports whether a key event is someone typing, which shortcuts
// leave alone.
export const typing = (e) => e.target instanceof Element && (e.target.closest("input, textarea, select, [contenteditable]") !== null);

export function wireShortcuts() {
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
      const route = { o: ["overview"], p: ["profiles"], a: ["logs"], l: ["logs"], e: ["explain"], s: ["settings"], t: ["settings", "tenants"], u: ["setup"] }[e.key];
      if (route) { e.preventDefault(); go(...route); }
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

