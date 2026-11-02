import { api, report } from "./api.js";
import { h, icon, clear, edit, toast, copyButton, qrCode } from "./dom.js";
import { section } from "./profiles.js";
import { state, isOperator } from "./state.js";

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

// connectSection shows how to point a device at profile p: the encrypted
// DNS endpoints that select it, and instructions per platform, from the
// server's setup endpoint. Reading it needs no admin token.
export function connectSection(p) {
  const id = p.id;
  const body = h("div", { class: "connect", "aria-live": "polite" }, h("p", { class: "muted", text: "Loading…" }));

  const device = h("input", {
    value: state.connect.device, placeholder: "living-room-tv", "aria-label": "Device name",
    spellcheck: "false", autocomplete: "off", autocapitalize: "none", maxlength: 63,
  });
  const deviceError = h("span", { class: "field-error", role: "alert" });
  const deviceRow = h("label", { class: "device-name" },
    h("span", { text: "Device name" }),
    device,
    h("span", { class: "muted hint", text: "Optional: lower-case letters, digits, and hyphens. Logs show it." }),
    deviceError,
  );

  let request = 0;
  const load = async () => {
    const name = device.value.trim().toLowerCase();
    const ok = validDevice(name);
    device.setAttribute("aria-invalid", String(!ok));
    deviceError.textContent = ok ? "" : "Use lower-case letters, digits, and single hyphens, starting and ending with a letter or digit.";
    if (!ok) return;
    state.connect.device = name;

    const mine = ++request;
    try {
      const setup = await api("GET", `/profiles/${encodeURIComponent(id)}/setup`, { query: { device: name } });
      if (mine === request) renderSetup(body, setup);
    } catch (err) {
      if (mine === request) clear(body).append(h("p", { class: "error", text: err.message }));
    }
  };

  let timer;
  device.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(load, 250);
  });
  load();

  return h("div", {},
    section("Connect a device",
      "Point a phone, tablet, or computer at this profile. The profile ID isn't a secret: anyone who knows it can use this profile.",
      deviceRow, body),
    sendSection(p, () => (validDevice(device.value.trim().toLowerCase()) ? device.value.trim().toLowerCase() : "")));
}

// sendSection makes a short-lived link to a setup page for the device to
// open itself: shared over AirDrop or a message, or copied.
export function sendSection(p, deviceName) {
  const out = h("div", { class: "send-result", "aria-live": "polite" });
  const make = edit(h("button", { type: "button", class: "primary" }, icon("arrow"), "Create a setup link"));
  make.addEventListener("click", async () => {
    make.disabled = true;
    try {
      const link = await api("POST", `/profiles/${encodeURIComponent(p.id)}/setup-links`, { query: { device: deviceName() } });
      const url = h("output", { class: "send-url mono", text: link.url });
      const copy = h("button", { type: "button" }, icon("copy"), "Copy");
      copy.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(link.url); toast("Copied the setup link."); } catch { toast("Select the link and copy it."); }
      });
      const share = navigator.share
        ? h("button", { type: "button", class: "primary" }, icon("arrow"), "Share")
        : null;
      share?.addEventListener("click", () => navigator.share({ title: `Set up ${p.name || p.id}`, url: link.url }).catch(() => {}));
      const until = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(new Date(link.expires));
      // Node.append would write a missing part as the text "null".
      clear(out).append(...[
        link.qr && h("div", { class: "send-qr" }, qrCode(link.qr, `QR code for the setup link for ${p.name || p.id}`),
          h("p", {}, h("strong", { text: "Scan it with the device's camera" }), h("span", { class: "muted", text: ` or open the link there. It works until ${until}.` }))),
        url,
        h("div", { class: "send-actions" }, share, copy),
        !link.qr && h("p", { class: "muted hint", text: `Open it on the device itself. It works until ${until}.` }),
      ].filter(Boolean));
    } catch (err) {
      clear(out).append(h("p", { class: "muted", text: err.status === 409
        ? (isOperator() ? "Setup links need this server's public name and DoH: start it with --hostname and a certificate." : "Setup links aren't available on this server yet. Ask its operator.")
        : err.message }));
    } finally {
      make.disabled = state.readOnly;
    }
  });
  return section("Send to a device",
    "A link to open on the phone or tablet you're setting up, with one-tap install on Apple devices. It works for 30 minutes.",
    make, out);
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
