import { services } from "./apps.js";

// The UI never holds an API token: the server signs the browser in with an
// HttpOnly session cookie, which fetch sends to this origin by itself.
export const state = {
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

export const isAdmin = () => state.auth?.session?.role === "admin";

// isOperator reports whether the UI acts as the server's operator, rather
// than for a tenant: the server tells tenants which one they are.
export const isOperator = () => !state.status?.tenant;

export const tenantOf = (id) => state.tenants.find((t) => t.id === id);

export const tenantName = (id) => tenantOf(id)?.name || id;

// ---------- passkeys ----------

export function profile() {
  return state.profiles.find((p) => p.id === state.selected);
}

export function replaceProfile(p) {
  const i = state.profiles.findIndex((x) => x.id === p.id);
  if (i >= 0) state.profiles[i] = p;
  else state.profiles.push(p);
}

export const profileName = (id) => { const p = state.profiles.find((x) => x.id === id); return p?.name || id; };
