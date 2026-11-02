import { api, report } from "./api.js";
import { buddy, clear, copyButton, edit, h, icon, qrCode, toast } from "./dom.js";
import { burst, enter } from "./motion.js";
import { section } from "./profiles.js";
import { routeHash } from "./routes.js";
import { isOperator, state } from "./state.js";
import { deviceQuery, linkSince, sleep, watch } from "./watch.js";

// DEVICE_NAME matches device names: DNS labels of lower-case letters,
// digits, and single hyphens, as the server requires.
export const DEVICE_NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

export const validDevice = (name) => name === "" || (DEVICE_NAME.test(name) && !name.includes("--"));

// guessPlatform picks the platform of the browser showing the UI, which is
// often the device being set up.
export function guessPlatform() {
  const ua = navigator.userAgent;
  if (/iPhone|iPad|Macintosh/.test(ua)) return "apple";
  if (/Android/.test(ua)) return "android";
  if (/Windows/.test(ua)) return "windows";
  if (/Linux/.test(ua)) return "linux";
  return "";
}

// deviceField is the device name input that the setup link and the
// settings by hand share, validated as people type.
export function deviceField(onChange) {
  const input = h("input", {
    value: state.connect.device, placeholder: "kids-ipad", "aria-label": "Device name",
    spellcheck: "false", autocomplete: "off", autocapitalize: "none", maxlength: 63, enterkeyhint: "done",
  });
  const error = h("span", { class: "field-error", role: "alert" });
  const value = () => {
    const name = input.value.trim().toLowerCase();
    return validDevice(name) ? name : null;
  };
  let timer;
  input.addEventListener("input", () => {
    const ok = value() !== null;
    input.setAttribute("aria-invalid", String(!ok));
    error.textContent = ok ? "" : "Use lower-case letters, digits, and single hyphens, starting and ending with a letter or digit.";
    if (!ok) return;
    state.connect.device = value();
    clearTimeout(timer);
    timer = setTimeout(() => onChange?.(value()), 250);
  });
  const row = h("label", { class: "device-name" },
    h("span", { text: "Device name" }),
    input,
    h("span", { class: "muted hint", text: "So you'll know it in Activity. Lower-case letters, digits, and hyphens." }),
    error,
  );
  return { row, value: () => value() ?? "" };
}

// connectSection shows how to point a device at profile p: first, a setup
// link to open on the device, which then says when it's connected; then,
// for doing it by hand, the encrypted DNS endpoints that select it, and
// steps per platform, from the server's setup endpoint.
export function connectSection(p) {
  const id = p.id;
  const body = h("div", { class: "connect", "aria-live": "polite" }, h("p", { class: "muted", text: "Loading…" }));

  let request = 0;
  const load = async (name) => {
    const mine = ++request;
    try {
      const setup = await api("GET", `/profiles/${encodeURIComponent(id)}/setup`, { query: { device: name } });
      if (mine === request) renderSetup(body, setup);
    } catch (err) {
      if (mine === request) clear(body).append(h("p", { class: "error", text: err.message }));
    }
  };
  const device = deviceField(load);
  load(device.value());

  return h("div", { class: "connect-flow" },
    section("", "Name the device, then open a setup link on it. doh says the moment it's connected.", device.row),
    setupLinkFlow(p, device.value),
    h("details", { class: "fine-tune by-hand" },
      h("summary", {}, h("span", { text: "Set it up by hand" }), h("span", { class: "muted", text: "Addresses and steps for each platform" })),
      h("p", { class: "muted hint", text: "The profile ID isn't a secret: anyone who knows it can use this profile." }),
      body));
}

// TRANSPORTS name how a device asked, for people.
const TRANSPORTS = { doh: "DNS-over-HTTPS", dot: "DNS-over-TLS", doq: "DNS-over-QUIC", udp: "plain DNS", tcp: "plain DNS" };

// setupLinkFlow makes a short-lived link to a setup page for the device to
// open itself, shared over AirDrop or a message, scanned, or copied; then
// waits, politely, for the device's first question, and says so when it
// comes. onConnected(device) runs then.
export function setupLinkFlow(p, deviceName, { onConnected } = {}) {
  const out = h("div", { class: "send-result" });
  const make = edit(h("button", { type: "button", class: "primary" }, icon("link"), "Create a setup link"));
  let watching = null;
  make.addEventListener("click", async () => {
    make.disabled = true;
    watching?.abort();
    try {
      const device = deviceName();
      const link = await api("POST", `/profiles/${encodeURIComponent(p.id)}/setup-links`, { query: { device } });
      const url = h("output", { class: "send-url mono", text: link.url });
      const copy = h("button", { type: "button" }, icon("copy"), "Copy");
      copy.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(link.url); toast("Copied the setup link."); } catch { toast("Select the link and copy it."); }
      });
      const share = navigator.share ? h("button", { type: "button" }, icon("share"), "Share") : null;
      share?.addEventListener("click", () => navigator.share({ title: `Set up ${p.name || p.id}`, url: link.url }).catch(() => {}));
      const until = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(new Date(link.expires));
      const status = h("div", { class: "watch", role: "status" });
      // Node.append would write a missing part as the text "null".
      clear(out).append(...[
        h("div", { class: "send-link" },
          link.qr ? qrCode(link.qr, `QR code for the setup link for ${p.name || p.id}`) : null,
          h("div", { class: "send-text" },
            h("p", {}, h("strong", { text: link.qr ? "Scan it with the device's camera" : "Open it on the device" }),
              h("span", { class: "muted", text: `, or send it the link. It works until ${until}, once per device.` })),
            url,
            h("div", { class: "send-actions" }, share, copy))),
        status,
      ].filter(Boolean));
      enter(out.firstElementChild);
      make.textContent = "";
      make.append(icon("link"), "Make a new link");
      watching = watchFor(status, p, device, link, onConnected);
    } catch (err) {
      clear(out).append(h("p", { class: "muted", text: err.status === 409
        ? (isOperator() ? "Setup links need this server's public name and DoH: start it with --hostname and a certificate. Until then, set devices up by hand, below." : "Setup links aren't available on this server yet. Ask its operator.")
        : err.message }));
    } finally {
      make.disabled = state.readOnly;
    }
  });
  return h("div", { class: "section send" }, make, out);
}

// watchFor shows that doh is waiting for device (or, unnamed, any new
// device) on profile p to ask its first question since link was made, and
// celebrates when it does. It stops when the link expires, or the status
// leaves the page; it waits while the page is hidden.
function watchFor(status, p, device, link, onConnected) {
  const ctl = new AbortController();
  const who = device || "the device";
  const waiting = () => clear(status).append(
    h("span", { class: "watch-ring", "aria-hidden": "true" }),
    h("div", {},
      h("p", { class: "watch-title" }, "Waiting for ", h("strong", { text: who }), " to connect…"),
      h("p", { class: "muted", text: "Open the link on it and follow its steps. This updates by itself." })));
  status.className = "watch waiting";
  waiting();

  const fetchDevices = async (query) => {
    if (!status.isConnected) { ctl.abort(); return null; }
    while (document.hidden && !ctl.signal.aborted) await new Promise((r) => document.addEventListener("visibilitychange", r, { once: true }));
    return api("GET", "/devices", { query, signal: ctl.signal });
  };
  const since = linkSince(link.expires);
  watch({
    query: deviceQuery(p.id, device, since), fetch: fetchDevices,
    until: new Date(link.expires).getTime(), signal: ctl.signal, sleep,
  }).then((found) => {
    if (!status.isConnected || ctl.signal.aborted) return;
    if (!found) {
      status.className = "watch expired";
      clear(status).append(icon("warn"), h("div", {},
        h("p", { class: "watch-title", text: "The link expired before anything connected." }),
        h("p", { class: "muted", text: "Make a new one, or set the device up by hand." })));
      return;
    }
    const name = found.device || found.hostname || found.client || "A device";
    const at = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(new Date(found.first));
    const art = buddy("happy");
    art.classList.add("watch-buddy");
    status.className = "watch connected";
    clear(status).append(art, h("div", {},
      h("p", { class: "watch-title" }, h("strong", { text: "Connected." }), ` ${name} is protected.`),
      h("p", { class: "muted", text: `It asked its first question at ${at}, over ${TRANSPORTS[found.transport] || found.transport}.` }),
      h("a", { class: "button small", href: routeHash("logs", "", { profile: p.id, client: found.client }) }, icon("log"), "See its activity")));
    burst(status);
    onConnected?.(found);
  });
  return ctl;
}

// renderSetup fills body with a setup's endpoints and instructions.
export function renderSetup(body, setup) {
  clear(body);

  const endpoints = [
    ["DNS-over-HTTPS", setup.doh_url],
    ["DNS-over-TLS", setup.dot_host],
    ["Plain DNS", (setup.dns_addrs || []).join(", ")],
  ].filter(([, v]) => v);
  if (endpoints.length) {
    body.append(h("dl", { class: "endpoints" }, endpoints.flatMap(([label, value]) => [
      h("dt", { text: label }),
      h("dd", {}, h("code", { text: value }), copyButton(value, label)),
    ])));
  }

  const platforms = setup.platforms || [];
  if (!platforms.length) return;

  const ids = platforms.map((pl) => pl.id);
  let current = ids.includes(state.connect.platform) ? state.connect.platform
    : ids.includes(guessPlatform()) ? guessPlatform() : ids[0];

  const tabs = h("div", { class: "segmented", role: "tablist", "aria-label": "Platform" });
  const panel = h("div", { class: "platform", role: "tabpanel" });

  const select = (platformID, focus = false) => {
    current = platformID;
    state.connect.platform = platformID;
    for (const tab of tabs.children) {
      const on = tab.dataset.platform === platformID;
      tab.setAttribute("aria-selected", String(on));
      tab.tabIndex = on ? 0 : -1;
      if (on && focus) tab.focus();
    }
    const pl = platforms.find((x) => x.id === platformID);
    panel.setAttribute("aria-label", pl.name);
    clear(panel).append(h("ol", { class: "steps" }, pl.steps.map((step) => h("li", { text: step }))));
    if (pl.id === "apple" && pl.download) panel.append(appleDownloads(setup));
  };

  for (const pl of platforms) {
    tabs.append(h("button", {
      type: "button", role: "tab", text: pl.name, "data-platform": pl.id,
      onClick: () => select(pl.id),
    }));
  }
  // Arrow keys move between tabs, as WAI-ARIA's tabs pattern describes.
  tabs.addEventListener("keydown", (e) => {
    const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
    if (!step) return;
    e.preventDefault();
    const i = ids.indexOf(current);
    select(ids[(i + step + ids.length) % ids.length], true);
  });

  body.append(tabs, panel);
  select(current);
}

// appleDownloads offers configuration profiles for Apple devices.
export function appleDownloads(setup) {
  const buttons = h("div", { class: "downloads" });
  const offer = (label, protocol, primary) => buttons.append(h("button", {
    type: "button", class: primary ? "primary" : "", text: label,
    onClick: (e) => downloadMobileConfig(setup, protocol, e.currentTarget),
  }));
  if (setup.doh_url) offer("Download configuration profile", "https", true);
  if (setup.dot_host) offer(setup.doh_url ? "DNS-over-TLS version" : "Download configuration profile", "tls", !setup.doh_url);
  buttons.append(h("p", { class: "muted hint", text: "Configuration profiles aren't signed, so devices show them as unverified. Downloading again replaces the installed one." }));
  return buttons;
}

// downloadMobileConfig fetches a configuration profile, so a failure can be
// shown here rather than saved as a file, and saves it through a temporary
// object URL.
export async function downloadMobileConfig(setup, protocol, button) {
  button.disabled = true;
  try {
    const resp = await api("GET", `/profiles/${encodeURIComponent(setup.profile)}/apple.mobileconfig`, {
      query: { device: setup.device, protocol }, raw: true,
    });
    const blob = await resp.blob();
    const name = [setup.profile, setup.device].filter(Boolean).join("-") + ".mobileconfig";

    const url = URL.createObjectURL(blob);
    const a = h("a", { href: url, download: name, hidden: true });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    toast(`Downloaded ${name}`);
  } catch (err) {
    report(err);
  } finally {
    button.disabled = false;
  }
}
