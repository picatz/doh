import { report } from "./api.js";
import { state } from "./state.js";

export const $ = (id) => document.getElementById(id);

// h builds an element. attrs: class, text, on{Event} listeners, dataset
// via data-*, booleans set as properties; children are nodes or strings.
export function h(tag, attrs = {}, ...children) {
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
export const count = (n, noun) => `${fmtNum(n)} ${noun}${n === 1 ? "" : "s"}`;

// badge returns a rounded square with someone's or something's initial,
// or an icon, as cards across the UI use to be told apart at a glance.
export function badge(name, sym = "") {
  const initial = (String(name).match(/\p{L}|\p{N}/u)?.[0] || "?").toUpperCase();
  return h("span", { class: "id-badge", "aria-hidden": "true" }, sym ? icon(sym) : initial);
}

// icon returns one of the page's icons, by its symbol's ID without the
// "i-" prefix, hidden from assistive technology: what it means is always
// said in words beside it.
export const SVG = "http://www.w3.org/2000/svg";

export function icon(name, className = "") {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("class", ("icon " + className).trim());
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(SVG, "use");
  use.setAttribute("href", "#i-" + name);
  svg.append(use);
  return svg;
}

export function clear(el) {
  el.replaceChildren();
  return el;
}

// edit marks a control as editing the policy, disabling it when read-only.
export function edit(el) {
  el.classList.add("edit");
  if (state.readOnly) el.disabled = true;
  return el;
}

// toast tells someone what just happened. With an action, such as Undo,
// it stays longer, and pauses while pointed at or focused, so there's
// time to use it.
export function toast(message, { error = false, details = [], action = null } = {}) {
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

export const nf = new Intl.NumberFormat();

export const fmtNum = (n) => nf.format(n ?? 0);

export function fmtTime(s, withDate = false) {
  if (!s) return "—";
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return "—";
  return withDate ? d.toLocaleString() : d.toLocaleTimeString();
}

export function fmtDuration(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const d = Math.floor(s / 86400), hr = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${hr}h`;
  if (hr) return `${hr}h ${m}m`;
  if (m) return `${m}m`;
  return `${s}s`;
}

export const plural = (n, one, many = one + "s") => `${fmtNum(n)} ${n === 1 ? one : many}`;

// buddy returns the character in a mood: "calm", "alert", or "happy".
export function buddy(mood) {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("class", "buddy");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(SVG, "use");
  use.setAttribute("href", "#buddy-" + mood);
  svg.append(use);
  return svg;
}

// emptyState says, with the character, that there's nothing here yet,
// and what to do about it.
export function emptyState({ mood = "calm", title, body = "", action = null, compact = false }) {
  const art = buddy(mood);
  art.classList.add("big");
  return h("div", { class: "empty-state" + (compact ? " compact" : "") }, art,
    h("p", { class: "empty-title" }, h("strong", { text: title })),
    body ? h("p", { class: "muted empty-body", text: body }) : null,
    action);
}

// copyButton copies text to the clipboard.
export function copyButton(text, label) {
  return h("button", {
    type: "button", class: "small", "aria-label": `Copy ${label}`,
    onClick: () => navigator.clipboard?.writeText(text).then(() => toast(`Copied ${label}`), () => toast("Couldn't copy", { error: true })),
  }, icon("copy"), "Copy");
}

// qrCode shows the server's QR code as an image: an image runs no
// scripts, and the page's policy allows data: images.
export function qrCode(q, label) {
  return h("img", { class: "qr", src: `data:image/svg+xml,${encodeURIComponent(q.svg)}`, alt: label, width: 176, height: 176 });
}

// confirmDialog asks before something that can't be undone, naming the
// action on its button: "Delete", "Revoke", "Remove".
export function confirmDialog(title, text, action = "Delete") {
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

// statusIcon marks a status with an icon from the set, sized to its text;
// the words beside it say the same, so color and shape are never alone.
export const statusIcon = (name) => icon(name, "status-icon");
