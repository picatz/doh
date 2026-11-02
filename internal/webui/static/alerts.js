import { showSecret } from "./accounts.js";
import { api, APIError, report } from "./api.js";
import { $, clear, confirmDialog, emptyState, h, icon, statusIcon, toast } from "./dom.js";
import { fromNow } from "./format.js";
import { PushError, prepare, pushSupported, subscribe, thisBrowser, unsubscribe } from "./push.js";
import { isAdmin, isOperator, state } from "./state.js";

// ALERT_KINDS says what each kind of alert is about, in a person's words.
export const ALERT_KINDS = {
  threat: ["Threats blocked", "A device tried to reach a phishing, malware, or tunneling domain. Sent even in quiet hours."],
  "new-device": ["New devices", "Something new started using this server, after an hour of getting to know the network."],
  failing: ["Lookups failing", "Many queries are failing, so sites may not load."],
  "list-failed": ["Lists that didn't load", "A blocklist couldn't be fetched or read, so it's out of date."],
};

// TYPES name each kind of destination, for people.
export const TYPES = { push: "Browser", email: "Email", ntfy: "ntfy", webhook: "Webhook" };

// PUSH_SERVICES name browsers' push services by host, for people.
const PUSH_SERVICES = [
  ["fcm.googleapis.com", "Chrome, Edge, or Android"],
  ["updates.push.services.mozilla.com", "Firefox"],
  ["web.push.apple.com", "Safari"],
  ["notify.windows.com", "Edge on Windows"],
];

// pushService names the browser a push destination's URL reaches.
export function pushService(url) {
  let host = "";
  try { host = new URL(url).hostname; } catch { return "a browser"; }
  return PUSH_SERVICES.find(([h]) => host === h || host.endsWith("." + h))?.[1] || host;
}

// alertsTenant is whose alerts the operator is looking at: "" for their
// own.
export let alertsTenant = "";

export const alertsQuery = () => (isOperator() && alertsTenant ? { tenant: alertsTenant } : undefined);

// available are the destination types the server offers, as the last
// GET /alerts said.
let available = ["ntfy", "webhook"];

// renderAlerts shows alert settings, destinations, and recent deliveries,
// to admins: destinations' URLs can be enough to read the alerts.
export async function renderAlerts() {
  if (!isAdmin()) return;
  // Ready the service worker and push key now, so a tap on "Notify this
  // browser" has nothing to wait for: Safari allows subscribing only
  // just after one.
  if (pushSupported()) prepare(api);
  if (!$("alerts").childElementCount) $("alerts").append(h("p", { class: "muted", text: "Loading alerts…" }));
  let data;
  try {
    data = await api("GET", "/alerts", { query: alertsQuery() });
  } catch (err) {
    const why = err instanceof APIError && err.status === 403
      ? "Alerts are set up by an admin person, or the server's operator."
      : `Alerts couldn't be loaded: ${err.message}`;
    clear($("alerts")).append(h("p", { class: err.status === 403 ? "muted" : "error", text: why }));
    return;
  }
  available = data.available_types || available;
  const mine = await thisBrowser(data.destinations).catch(() => null);
  const box = clear($("alerts"));
  $("alerts-test").disabled = !data.destinations.some((d) => d.state === "active");
  if (!alertsTenant) state.hints.alerts = data.destinations.filter((d) => d.state === "active").length;

  if (isOperator() && state.tenants.length) {
    const pick = h("select", { "aria-label": "Whose alerts" },
      h("option", { value: "", text: "Yours, as the operator" }),
      state.tenants.map((t) => h("option", { value: t.id, text: t.name || t.id })));
    pick.value = alertsTenant;
    pick.addEventListener("change", () => { alertsTenant = pick.value; renderAlerts().catch(report); });
    box.append(h("label", { class: "alerts-for" }, "Alerts for ", pick));
  }

  // This browser comes first: for most people, it's the one to turn on.
  if (!alertsTenant && available.includes("push")) box.append(thisBrowserSection(mine));

  // What to hear about.
  const kinds = h("div", { class: "toggle-list" });
  for (const kind of data.available_kinds) {
    const [title, desc] = ALERT_KINDS[kind] || [kind, ""];
    const input = h("input", { type: "checkbox", role: "switch", checked: data.settings.kinds.includes(kind), "aria-label": title });
    input.addEventListener("change", () => {
      const on = new Set(data.settings.kinds);
      if (input.checked) on.add(kind); else on.delete(kind);
      saveAlertSettings({ kinds: data.available_kinds.filter((k) => on.has(k)) }, input.checked ? `${title}: on` : `${title}: off`, input);
    });
    kinds.append(h("div", { class: "toggle" }, h("div", { class: "title", text: title }), h("div", { class: "control" }, input), h("div", { class: "desc", text: desc })));
  }
  box.append(h("div", { class: "section" }, h("h4", { text: "What to hear about" }), kinds));

  box.append(quietHours(data.settings));
  box.append(destinationsList(data.destinations, mine));

  if (data.deliveries.length) {
    box.append(h("div", { class: "section" }, h("h4", { text: "Recently sent" }),
      h("ul", { class: "deliveries" }, data.deliveries.slice(0, 5).map((d) => h("li", {},
        deliveryStatus(d),
        h("div", {},
          h("div", { class: "delivery-summary", text: d.summary }),
          h("div", { class: "muted", text: `To ${destinationName(data.destinations, d.destination)} · ${fromNow(d.time)}${d.ok ? "" : " · " + (d.error || "failed")}` })),
      )))));
  }
}

// whyNoPush says why this browser can't get notifications from the page.
function whyNoPush() {
  if (!globalThis.isSecureContext) return "Notifications need the page opened over https, or at localhost.";
  if (/iPhone|iPad/.test(navigator.userAgent)) return "On iPhone and iPad, add doh to the Home Screen first (Share, then Add to Home Screen), and open it from there.";
  return "This browser can't show notifications from web pages. Try another, or use ntfy or email.";
}

// browserName guesses a name for this browser's destination, such as
// "Firefox on Mac", which people can change in the list.
export function browserName(ua = navigator.userAgent) {
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android" : /Mac OS X/.test(ua) ? "Mac" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}

// thisBrowserSection offers notifications in this browser, or says
// they're on, or why they can't be.
function thisBrowserSection(mine) {
  const section = h("div", { class: "section this-browser" }, h("h4", { text: "This browser" }));
  const row = (iconName, title, text, ...actions) => section.append(h("div", { class: "browser-row" },
    h("span", { class: "id-badge", "aria-hidden": "true" }, icon(iconName)),
    h("div", {}, h("p", { class: "browser-title" }, title), h("p", { class: "muted", text })),
    actions.length ? h("div", { class: "row-actions" }, ...actions) : null));

  if (!pushSupported()) {
    row("bell", "Notifications aren't available here", whyNoPush());
    return section;
  }
  if (mine?.state === "active") {
    row("check", h("span", { class: "status ok" }, statusIcon("check"), "On for this browser"),
      `Alerts show up here as notifications, even with doh closed, as "${mine.name || browserName()}".`,
      h("button", { type: "button", onClick: (e) => turnOff(e.currentTarget) }, "Turn off"));
    return section;
  }
  if (globalThis.Notification?.permission === "denied") {
    row("warn", h("span", { class: "status warn" }, statusIcon("warn"), "Notifications are blocked"),
      "This browser was told not to show doh's notifications. Allow them in its site settings for this page, then come back.");
    return section;
  }
  row("bell", mine?.state === "gone" ? h("span", { class: "status warn" }, statusIcon("warn"), "This browser's notifications stopped") : "Notify this browser",
    mine?.state === "gone"
      ? "Its push service said the subscription ended, as happens when site data is cleared. Turn them on again to keep getting alerts here."
      : "Get alerts here as notifications, even with doh closed. The browser asks first.",
    h("button", { type: "button", class: "primary", onClick: (e) => notifyThisBrowser(e.currentTarget) }, icon("bell"), mine ? "Turn on again" : "Notify this browser"));
  return section;
}

// notifyThisBrowser subscribes this browser, from a click, as browsers
// require.
export async function notifyThisBrowser(button) {
  if (button) button.disabled = true;
  try {
    const d = await subscribe(api, { name: browserName() });
    toast(`Notifications are on for ${d.name || "this browser"}. Send a test to see one.`);
    document.dispatchEvent(new CustomEvent("doh:alerts-changed"));
  } catch (err) {
    if (err instanceof PushError) toast(err.message, { error: err.code !== "denied" });
    else report(err);
  } finally {
    if (button) button.disabled = false;
    await renderAlerts().catch(report);
  }
}

async function turnOff(button) {
  button.disabled = true;
  try {
    const data = await api("GET", "/alerts");
    await unsubscribe(api, data.destinations);
    toast("Notifications are off for this browser.");
  } catch (err) {
    report(err);
  } finally {
    await renderAlerts().catch(report);
  }
}

// destinationName names a destination by its ID, for deliveries.
export function destinationName(destinations, id) {
  const d = destinations.find((x) => x.id === id);
  return d ? d.name || displayURL(d) : "a removed destination";
}

// displayURL says where a destination is, for people.
function displayURL(d) {
  if (d.type === "email") return d.url.replace(/^mailto:/, "");
  if (d.type === "push") return `Notifications in ${pushService(d.url)}`;
  return d.url;
}

// deliveryStatus says how a delivery went, by symbol and word as well as
// color.
export function deliveryStatus(d) {
  return d.ok
    ? h("span", { class: "status ok", title: "Delivered" }, statusIcon("check"), h("span", { class: "visually-hidden", text: "Delivered: " }))
    : h("span", { class: "status bad", title: d.error || "Failed" }, statusIcon("block"), h("span", { class: "visually-hidden", text: "Failed: " }));
}

// quietHours edits the daily period when only threats are sent.
export function quietHours(settings) {
  const q = settings.quiet_hours;
  const zone = settings.time_zone || Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  const toggle = h("input", { type: "checkbox", role: "switch", checked: !!q, "aria-label": "Quiet hours" });
  const start = h("input", { type: "time", value: q?.start || "22:00", "aria-label": "Quiet hours start" });
  const end = h("input", { type: "time", value: q?.end || "07:00", "aria-label": "Quiet hours end" });
  const times = h("div", { class: "quiet-times" }, start, h("span", { class: "muted", text: "to" }), end,
    h("span", { class: "muted", text: zone.replaceAll("_", " ") }));
  times.hidden = !q;
  const save = (msg) => saveAlertSettings(
    toggle.checked ? { quiet_hours: { start: start.value, end: end.value }, time_zone: zone } : { quiet_hours: null },
    msg, toggle);
  toggle.addEventListener("change", () => { times.hidden = !toggle.checked; save(toggle.checked ? `Quiet hours: ${start.value} to ${end.value}` : "Quiet hours: off"); });
  for (const input of [start, end]) input.addEventListener("change", () => { if (start.value && end.value) save(`Quiet hours: ${start.value} to ${end.value}`); });
  return h("div", { class: "section" }, h("h4", { text: "When" }),
    h("div", { class: "toggle" },
      h("div", { class: "title", text: "Quiet hours" }),
      h("div", { class: "control" }, toggle),
      h("div", { class: "desc", text: "Only threats come through, and the rest wait until it's over, summed up." })),
    times);
}

export async function saveAlertSettings(patch, message, input) {
  if (input) input.disabled = true;
  try {
    await api("PATCH", "/alerts", { body: patch, patch: true, query: alertsQuery() });
    toast(message);
  } catch (err) {
    report(err);
  }
  await renderAlerts().catch(report);
}

// destinationState says whether a destination gets alerts, in words and
// a symbol: active ones by how their last delivery went, email addresses
// waiting to be confirmed (or too late to be), and browsers whose
// subscriptions ended.
export function destinationState(d, now = Date.now()) {
  if (d.state === "pending") {
    if (d.confirm_by && new Date(d.confirm_by).getTime() <= now) {
      return { level: "bad", icon: "block", text: "Not confirmed in time",
        more: "The address wasn't confirmed within a day, so nothing goes there. Remove it, and add it again for a new email." };
    }
    return { level: "warn", icon: "warn", text: "Waiting for confirmation", pending: true,
      more: `doh emailed this address a link and a code. Nothing is sent until someone opens the link and presses Confirm, or gives you the code to enter here${d.confirm_by ? `, ${fromNow(d.confirm_by, now)}` : ""}.` };
  }
  if (d.state === "gone") {
    return { level: "warn", icon: "warn", text: "Stopped",
      more: "The browser's push service said this subscription ended. Turn notifications on again in that browser, or remove it." };
  }
  const failedLast = d.last_failure && (!d.last_success || new Date(d.last_failure) > new Date(d.last_success));
  if (failedLast) return { level: "bad", icon: "block", text: `Failed ${fromNow(d.last_failure, now)}`, error: d.last_error };
  if (d.last_success) return { level: "ok", icon: "check", text: `Delivered ${fromNow(d.last_success, now)}` };
  return { level: "", icon: "", text: "Nothing sent yet" };
}

// destinationsList lists where alerts go, of every kind, and how each is
// doing.
export function destinationsList(destinations, mine) {
  const body = destinations.length
    ? h("ul", { class: "passkeys" }, destinations.map((d) => {
      const st = destinationState(d);
      const where = displayURL(d);
      return h("li", { class: "passkey destination" },
        h("div", { class: "passkey-name" }, d.name || where,
          h("span", { class: "badge", text: TYPES[d.type] || d.type }),
          mine?.id === d.id ? h("span", { class: "badge you", text: "This browser" }) : null),
        d.name ? h("span", { class: "passkey-meta dest-url", text: where }) : null,
        h("div", { class: "passkey-meta" }, h("span", { class: `status ${st.level}`.trim() }, st.icon ? statusIcon(st.icon) : null, st.text)),
        st.more ? h("p", { class: "passkey-meta muted dest-more", text: st.more }) : null,
        st.error ? h("div", { class: "passkey-meta dest-error", text: st.error }) : null,
        st.pending ? confirmForm(d) : null,
        h("button", { type: "button", class: "ghost danger-text", text: "Remove", "aria-label": `Remove ${d.name || where}`, onClick: () => removeDestination(d) }),
      );
    }))
    : emptyState({
      mood: "alert", compact: true,
      title: "Alerts have nowhere to go yet.",
      body: available.includes("push") && pushSupported()
        ? "Turn on notifications in this browser above, or add your email, ntfy, or a webhook."
        : "Add ntfy to get them on your phone in a minute, with its free app.",
      action: h("button", { type: "button", class: "primary", onClick: () => openAddDestination(available.includes("email") ? "email" : "ntfy") }, icon("plus"), "Add a destination"),
    });
  return h("div", { class: "section" }, h("h4", { text: "Where they go" }), body);
}

// confirmForm takes the code emailed to a pending address.
function confirmForm(d) {
  const code = h("input", {
    "aria-label": `Code emailed to ${d.url.replace(/^mailto:/, "")}`, placeholder: "ABCDE-FGHJK",
    autocomplete: "one-time-code", spellcheck: "false", autocapitalize: "characters", maxlength: 16, required: true,
  });
  const form = h("form", { class: "chip-form confirm-code" }, code, h("button", { type: "submit" }, "Confirm"));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const button = form.querySelector("button");
    button.disabled = true;
    try {
      await api("POST", "/alerts/confirm", { body: { code: code.value.trim().toUpperCase() }, query: alertsQuery() });
      toast(`Confirmed. Alerts go to ${d.url.replace(/^mailto:/, "")} now.`);
      document.dispatchEvent(new CustomEvent("doh:alerts-changed"));
      await renderAlerts();
    } catch (err) {
      report(err);
      button.disabled = false;
    }
  });
  return form;
}

// NTFY is ntfy's public server, suggested for new destinations; the page
// never fetches it.
export const NTFY = "https://ntfy.sh/";

// ntfyTopic suggests a topic no one will guess: on ntfy, knowing a topic
// is all it takes to read it.
export function ntfyTopic() {
  const bytes = crypto.getRandomValues(new Uint8Array(9));
  const alphabet = "abcdefghijkmnpqrstuvwxyz23456789";
  return NTFY + "doh-" + [...bytes].map((b) => alphabet[b % alphabet.length]).join("");
}

export function alertTypeChanged() {
  const type = $("alert-form").querySelector('input[name="alert-type"]:checked').value;
  const url = $("alert-url");
  const email = type === "email";
  $("alert-url-field").hidden = email;
  $("alert-address-field").hidden = !email;
  url.required = !email;
  $("alert-address").required = email;
  if (email) return;
  if (type === "ntfy") {
    if (!url.value || !url.value.startsWith(NTFY)) url.value = ntfyTopic();
    url.placeholder = NTFY + "your-topic";
    $("alert-url-hint").textContent = "Subscribe to this topic in the ntfy app. Anyone who knows the topic can read what's sent to it, so keep it hard to guess. Your own ntfy server works too.";
  } else {
    if (url.value.startsWith(NTFY)) url.value = "";
    url.placeholder = "https://example.com/hooks/doh";
    $("alert-url-hint").textContent = "An https URL. Each delivery is signed as Standard Webhooks describes, with a secret shown once you add it.";
  }
}

export function openAddDestination(type = "ntfy") {
  const form = $("alert-form");
  form.reset();
  const hasEmail = available.includes("email");
  $("alert-type-email").hidden = !hasEmail;
  if (type === "email" && !hasEmail) type = "ntfy";
  form.querySelector(`input[name="alert-type"][value="${type}"]`).checked = true;
  $("alert-url").value = "";
  alertTypeChanged();
  $("alert-dialog").showModal();
  $("alert-name").focus();
}

export async function addDestination(e) {
  e.preventDefault();
  const form = $("alert-form");
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    const type = form.querySelector('input[name="alert-type"]:checked').value;
    const body = { type, name: $("alert-name").value.trim() };
    if (type === "email") body.address = $("alert-address").value.trim();
    else body.url = $("alert-url").value.trim();
    const created = await api("POST", "/alerts/destinations", { body, query: alertsQuery() });
    $("alert-dialog").close();
    await renderAlerts();
    document.dispatchEvent(new CustomEvent("doh:alerts-changed"));
    const d = created.destination;
    const name = d.name || displayURL(d);
    if (created.secret) {
      showSecret(`Signing secret for ${name}`, created.secret,
        "Check each delivery's webhook-signature header with it, so you know it came from this server.");
    } else if (d.state === "pending") {
      toast(`Emailed ${displayURL(d)} to confirm. Alerts start once it's confirmed.`);
    } else {
      toast(`Added ${name}. Send a test to check it.`);
    }
  } catch (err) {
    report(err);
  } finally {
    submit.disabled = false;
  }
}

export async function removeDestination(d) {
  const name = d.name || displayURL(d);
  if (!(await confirmDialog(`Remove ${name}?`, "Alerts stop going there at once.", "Remove"))) return;
  try {
    await api("DELETE", `/alerts/destinations/${encodeURIComponent(d.id)}`, { query: alertsQuery() });
    toast(`Removed ${name}.`);
    await renderAlerts();
  } catch (err) {
    report(err);
  }
}

export async function testAlerts() {
  const button = $("alerts-test");
  button.disabled = true;
  button.textContent = "Sending…";
  try {
    const result = await api("POST", "/alerts/test", { query: alertsQuery() });
    const failed = result.deliveries.filter((d) => !d.ok);
    if (!failed.length) toast(result.deliveries.length === 1 ? "Sent. Check that it arrived." : `Sent to all ${result.deliveries.length}. Check that they arrived.`);
    else toast(`Couldn't reach ${failed.map((d) => d.destination).join(", ")}: ${failed[0].error || "it failed"}`, { error: true });
  } catch (err) {
    report(err);
  } finally {
    button.textContent = "Send a test";
    await renderAlerts().catch(report);
  }
}
