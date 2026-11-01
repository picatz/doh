// The color theme: the system's, or one someone chose, remembered on this
// device. Storage can be unavailable, such as in a private window; then
// the choice lasts until the page is closed.

const KEY = "doh.theme";
const THEMES = ["system", "light", "dark"];

// currentTheme returns the remembered choice, or "system".
export function currentTheme() {
  try {
    const t = localStorage.getItem(KEY);
    return THEMES.includes(t) ? t : "system";
  } catch {
    return "system";
  }
}

// applyTheme shows theme and remembers it.
export function applyTheme(theme, root = document.documentElement) {
  if (theme === "system") delete root.dataset.theme;
  else root.dataset.theme = theme;
  try {
    if (theme === "system") localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, theme);
  } catch { /* not remembered: fine */ }
}

// nextTheme returns the theme after theme, in the order a toggle cycles.
export const nextTheme = (theme) => THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];

// themeLabel names a theme for people.
export const themeLabel = (theme) => ({ system: "Match the system", light: "Light", dark: "Dark" })[theme];

// The remembered theme applies as soon as this module loads, before the
// app draws anything.
applyTheme(currentTheme());
