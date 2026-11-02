// Preferences someone sets on this device that the server needn't know:
// that they dismissed the setup checklist, or set up their router. Kept
// under one key, beside the theme. Storage can be unavailable, such as in
// a private window; then a choice lasts until the page is closed.

const KEY = "doh.prefs";
const memory = {};

// readPrefs returns the remembered preferences.
export function readPrefs() {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) || "{}");
    return v && typeof v === "object" ? { ...v, ...memory } : { ...memory };
  } catch {
    return { ...memory };
  }
}

// setPref remembers one preference: a boolean.
export function setPref(name, value) {
  memory[name] = !!value;
  try {
    localStorage.setItem(KEY, JSON.stringify({ ...readPrefs(), [name]: !!value }));
  } catch { /* not remembered: fine */ }
}
