import { toast } from "./dom.js";
import { showSignIn, loadPolicy } from "./session.js";
import { state, isAdmin } from "./state.js";

export const API = "/api/v1";

export const AUTH = "/auth";

export class APIError extends Error {
  constructor(status, body) {
    super(body?.error || `HTTP ${status}`);
    this.status = status;
    this.details = body?.details || [];
  }
}

export async function api(method, path, { body, patch = false, query, signal, raw = false } = {}) {
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
export function report(err) {
  if (err.name === "AbortError") return;
  if (err instanceof APIError && [401, 403, 412].includes(err.status)) return;
  toast(err.message, { error: true, details: err.details || [] });
}

// ---------- sign-in ----------

// authCall calls a sign-in endpoint, returning its JSON, or throwing an
// APIError with the server's message.
export async function authCall(method, path, body) {
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
