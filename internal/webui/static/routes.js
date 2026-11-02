// Routes: every place in the UI has a URL, #/view or #/view/argument,
// with an optional query, so back, forward, reload, and links work.
// Sign-in links use #signin=..., handled apart. Pure, so it's tested on
// its own.

// VIEWS are the top-level places.
export const VIEWS = ["overview", "setup", "profiles", "logs", "explain", "settings"];

// SETTINGS are the Settings hub's sections, in the order it lists them.
// operator marks those only the server's operator sees; admin, those only
// admins see.
export const SETTINGS = [
  { id: "account", title: "Account & passkeys", icon: "user", group: "You" },
  { id: "people", title: "People", icon: "people", group: "Household" },
  { id: "alerts", title: "Alerts", icon: "bell", group: "Household", admin: true },
  { id: "api", title: "Service accounts & API", icon: "code", group: "Automation" },
  { id: "tenants", title: "Tenants", icon: "tenants", group: "Server", operator: true },
  { id: "server", title: "Server", icon: "server", group: "Server" },
];

// PROFILE_SECTIONS are a profile's sections, in the order it lists them.
export const PROFILE_SECTIONS = [
  { id: "connect", title: "Connect a device", icon: "phone" },
  { id: "protection", title: "Protection", icon: "security" },
  { id: "apps", title: "Apps & schedules", icon: "block" },
  { id: "rules", title: "Allow & deny", icon: "allow" },
  { id: "devices", title: "Devices & networks", icon: "system" },
  { id: "settings", title: "Profile settings", icon: "settings" },
];

// LEGACY are places that moved, and where they are now, so old links and
// bookmarks still land somewhere sensible.
const LEGACY = {
  security: ["settings", "account"],
  tenants: ["settings", "tenants"],
};

// parseRoute reads the view, its argument, such as a profile ID or a
// settings section, and its query from a URL hash. Unknown places are the
// Overview; moved ones are where they went, with moved set.
export function parseRoute(hash) {
  const m = /^#\/([a-z]+)(?:\/([^?]*))?(?:\?(.*))?$/.exec(hash || "");
  const query = new URLSearchParams(m?.[3] || "");
  if (!m) return { view: "overview", arg: "", query, moved: false };
  if (LEGACY[m[1]]) {
    const [view, arg] = LEGACY[m[1]];
    return { view, arg, query, moved: true };
  }
  if (!VIEWS.includes(m[1])) return { view: "overview", arg: "", query, moved: false };
  let arg = "";
  try { arg = decodeURIComponent(m[2] || ""); } catch { /* a malformed link: ignore its argument */ }
  if (m[1] === "settings" && arg && !SETTINGS.some((s) => s.id === arg)) arg = "";
  return { view: m[1], arg, query, moved: false };
}

// routeHash returns the URL hash of a view, its argument, and its query,
// leaving out empty query values.
export function routeHash(view, arg = "", query = {}) {
  const q = new URLSearchParams(Object.entries(query).filter(([, v]) => v !== undefined && v !== null && v !== ""));
  return `#/${view}${arg ? "/" + encodeURIComponent(arg) : ""}${q.size ? "?" + q : ""}`;
}

// settingsFor returns the Settings sections someone sees.
export const settingsFor = ({ operator, admin }) => SETTINGS.filter((s) => (!s.operator || operator) && (!s.admin || admin));
