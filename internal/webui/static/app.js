// doh admin UI: the entry point. Plain ES modules, no dependencies or
// build step; each view and feature is its own module.
//
// Everything shown can come from the network, and query names are chosen
// by whoever sends a query, so the DOM is only ever built with
// createElement and textContent: never from HTML strings.

import { copySecret, createAccount, openCreateAccount, submitRotate } from "./accounts.js";
import { applyLogFilter, closeDrawer, loadLogs, setLogFilter, startLive, stopLive } from "./activity.js";
import { addDestination, alertTypeChanged, openAddDestination, testAlerts } from "./alerts.js";
import { report } from "./api.js";
import { wirePalette, wireShortcuts, wireTheme } from "./commands.js";
import { $, clear } from "./dom.js";
import { runExplain } from "./explain.js";
import { loadHistory } from "./history.js";
import { loadSetup, renderSetupCard, renderSetupView } from "./onboarding.js";
import { renderOverview } from "./overview.js";
import { addPasskey } from "./people.js";
import { createProfile, openCreate, renderProfiles } from "./profiles.js";
import { applyRoute, register } from "./router.js";
import { signInWithPasskey, signOut, start } from "./session.js";
import { renderSettings, settingsTitle } from "./settings.js";
import { profile, state } from "./state.js";
import { createTenant, openCreateTenant } from "./tenants.js";

export function wire() {
  $("new-sa").addEventListener("click", openCreateAccount);
  $("sa-form").addEventListener("submit", createAccount);
  $("sa-cancel").addEventListener("click", () => $("sa-dialog").close());
  $("rotate-form").addEventListener("submit", submitRotate);
  $("rotate-cancel").addEventListener("click", () => $("rotate-dialog").close());
  $("secret-copy").addEventListener("click", copySecret);
  $("alerts-add").addEventListener("click", () => openAddDestination());
  $("alerts-test").addEventListener("click", testAlerts);
  $("history-more").addEventListener("click", () => loadHistory(false).catch(report));
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

// The views, by the names routes.js gives them.
register("overview", {
  title: () => "Overview",
  render: async () => { await renderOverview(); await loadSetup().catch(() => null); renderSetupCard(); },
  focus: () => $("overview-title"),
});
register("setup", {
  title: () => "Setup",
  render: renderSetupView,
  focus: () => $("setup-title"),
});
register("profiles", {
  title: () => profile()?.name || profile()?.id || "Profiles",
  route: (arg, query) => {
    if (state.selected !== arg) state.draft = null;
    state.selected = arg;
    state.profileTab = query.get("tab") || "";
  },
  render: renderProfiles,
  focus: () => (profile() ? $(state.profileTab ? "panel-title" : "profile-title") : $("profiles-title")),
});
register("logs", {
  title: () => "Activity",
  route: (arg, query) => setLogFilter(query),
  render: () => loadLogs(true),
  leave: stopLive,
  focus: () => $("logs-title"),
});
register("explain", {
  title: () => "Explain",
  render: () => { if (!$("explain-result").childElementCount) return runExplain(); },
  focus: () => $("explain-title"),
});
register("settings", {
  title: (arg) => (arg ? settingsTitle(arg) : "Settings"),
  render: renderSettings,
  focus: (arg) => (arg ? $("panel-" + arg)?.querySelector(".panel-title") : $("settings-title")),
});

wire();
start();
