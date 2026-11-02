import { fromNow } from "./format.js";
import { showSecret } from "./accounts.js";
import { APIError, api, report } from "./api.js";
import { $, h, clear, toast, confirmDialog, statusIcon } from "./dom.js";
import { section } from "./profiles.js";
import { start } from "./session.js";
import { state, isAdmin, isOperator } from "./state.js";

// ALERT_KINDS says what each kind of alert is about, in a person's words.
export const ALERT_KINDS = {
  threat: ["Threats blocked", "A device tried to reach a phishing, malware, or tunneling domain. Sent even in quiet hours."],
  "new-device": ["New devices", "Something new started using this server, after an hour of getting to know the network."],
  failing: ["Lookups failing", "Many queries are failing, so sites may not load."],
  "list-failed": ["Lists that didn't load", "A blocklist couldn't be fetched or read, so it's out of date."],
};

// alertsTenant is whose alerts the operator is looking at: "" for their
// own.
export let alertsTenant = "";

export const alertsQuery = () => (isOperator() && alertsTenant ? { tenant: alertsTenant } : undefined);

// renderAlerts shows alert settings, destinations, and recent deliveries,
// to admins: destinations' URLs can be enough to read the alerts.
export async function renderAlerts() {
  const section = $("alerts-section");
  section.hidden = !isAdmin();
  if (section.hidden) return;
  let data;
  try {
    data = await api("GET", "/alerts", { query: alertsQuery() });
  } catch (err) {
    if (err instanceof APIError && err.status === 403) { section.hidden = true; return; }
    throw err;
  }
  const box = clear($("alerts"));
  $("alerts-test").disabled = !data.destinations.length;

  if (isOperator() && state.tenants.length) {
    const pick = h("select", { "aria-label": "Whose alerts" },
      h("option", { value: "", text: "Yours, as the operator" }),
      state.tenants.map((t) => h("option", { value: t.id, text: t.name || t.id })));
    pick.value = alertsTenant;
    pick.addEventListener("change", () => { alertsTenant = pick.value; renderAlerts().catch(report); });
    box.append(h("label", { class: "alerts-for" }, "Alerts for ", pick));
  }

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
  box.append(destinationsList(data.destinations));

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

// destinationName names a destination by its ID, for deliveries.
export function destinationName(destinations, id) {
  const d = destinations.find((x) => x.id === id);
  return d ? d.name || d.url : "a removed destination";
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

// destinationsList lists where alerts go, and how each last went.
export function destinationsList(destinations) {
  const body = destinations.length
    ? h("ul", { class: "passkeys" }, destinations.map((d) => {
      const failedLast = d.last_failure && (!d.last_success || new Date(d.last_failure) > new Date(d.last_success));
      const health = failedLast
        ? h("span", { class: "status bad" }, statusIcon("block"), `Failed ${fromNow(d.last_failure)}`)
        : d.last_success
          ? h("span", { class: "status ok" }, statusIcon("check"), `Delivered ${fromNow(d.last_success)}`)
          : h("span", { class: "status", text: "Nothing sent yet" });
      return h("li", { class: "passkey" },
        h("div", { class: "passkey-name" }, d.name || d.url, h("span", { class: "badge", text: d.type === "ntfy" ? "ntfy" : "Webhook" })),
        d.name ? h("code", { class: "passkey-meta dest-url", text: d.url }) : null,
        h("div", { class: "passkey-meta" }, health),
        failedLast && d.last_error ? h("div", { class: "passkey-meta dest-error", text: d.last_error }) : null,
        h("button", { type: "button", class: "ghost danger-text", text: "Remove", "aria-label": `Remove ${d.name || d.url}`, onClick: () => removeDestination(d) }),
      );
    }))
    : h("p", { class: "muted empty" }, "Nowhere yet. ",
      h("button", { type: "button", class: "link", text: "Add ntfy", onClick: () => openAddDestination("ntfy") }),
      " to get alerts on your phone in a minute.");
  return h("div", { class: "section" }, h("h4", { text: "Where they go" }), body);
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
    const body = {
      type: form.querySelector('input[name="alert-type"]:checked').value,
      url: $("alert-url").value.trim(),
      name: $("alert-name").value.trim(),
    };
    const created = await api("POST", "/alerts/destinations", { body, query: alertsQuery() });
    $("alert-dialog").close();
    await renderAlerts();
    const name = created.destination.name || created.destination.url;
    if (created.secret) {
      showSecret(`Signing secret for ${name}`, created.secret,
        "Check each delivery's webhook-signature header with it, so you know it came from this server.");
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
  const name = d.name || d.url;
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

// ---------- theme ----------
