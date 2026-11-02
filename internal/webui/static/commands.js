import { Palette, looksLikeDomain } from "./palette.js";
import { currentTheme, applyTheme, nextTheme, themeLabel } from "./theme.js";
import { openCreateAccount } from "./accounts.js";
import { report } from "./api.js";
import { $, h, icon, toast } from "./dom.js";
import { explainDomain, findInActivity, changeDomain } from "./explain.js";
import { openCreate } from "./profiles.js";
import { go } from "./router.js";
import { signOut } from "./session.js";
import { state, isAdmin, isOperator } from "./state.js";
import { openCreateTenant } from "./tenants.js";

export function wireTheme() {
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

export function cycleTheme() {
  const t = nextTheme(currentTheme());
  applyTheme(t);
  wireTheme.sync?.();
  toast(`Theme: ${themeLabel(t)}`);
}

// ---------- command palette ----------

export let palette;

// commands returns what the palette offers for query: places, profiles,
// actions, and, for anything that looks like a domain, what can be done
// with it.
export function commands(query) {
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
