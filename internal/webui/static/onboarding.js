// Onboarding: a calm, guided setup for a new server, and a way back to it
// until it's done. The checklist is worked out from what the server knows
// (setup.js); this module draws it, and does each step in place.

import { notifyThisBrowser, openAddDestination } from "./alerts.js";
import { api, APIError, report } from "./api.js";
import { deviceField, setupLinkFlow } from "./connect.js";
import { $, buddy, clear, copyButton, h, icon, plural, toast } from "./dom.js";
import { burst, enter } from "./motion.js";
import { registerPasskey } from "./people.js";
import { readPrefs, setPref } from "./prefs.js";
import { pushSupported } from "./push.js";
import { sector } from "./ring.js";
import { go } from "./router.js";
import { routeHash } from "./routes.js";
import { plainDNSClients, progress, ROUTER_SEEN, setupSteps } from "./setup.js";
import { isAdmin, isOperator, state } from "./state.js";
import { renderWho } from "./session.js";

const SVG = "http://www.w3.org/2000/svg";

// loadSetup asks the server what the checklist needs: the devices it has
// answered, and, for admins, where alerts go. It keeps the result in
// state.setup and returns it.
export async function loadSetup() {
  const [devices, alerts] = await Promise.all([
    api("GET", "/devices").catch(() => ({ devices: [] })),
    isAdmin() ? api("GET", "/alerts").catch((err) => { if (err instanceof APIError && err.status === 403) return null; throw err; }) : null,
  ]);
  const steps = setupSteps({
    person: state.auth?.session?.person || "",
    admin: isAdmin(),
    operator: isOperator(),
    profiles: state.profiles,
    devices: devices?.devices || [],
    destinations: alerts ? alerts.destinations : null,
    prefs: readPrefs(),
  });
  state.setup = { steps, devices: devices?.devices || [], destinations: alerts?.destinations || [], since: devices?.since, ...progress(steps) };
  state.hints.setup = state.setup.complete ? "All done" : `${state.setup.done} of ${state.setup.total} done`;
  renderNudge();
  renderWho();
  return state.setup;
}

// progressRing draws the checklist as doh's ring: a segment per step,
// glazed and sprinkled once it's done.
export function progressRing(steps, { size = "" } = {}) {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 240 240");
  svg.setAttribute("class", "progress-ring " + size);
  svg.setAttribute("aria-hidden", "true");
  const n = Math.max(steps.length, 1), gap = 6;
  steps.forEach((s, i) => {
    const a0 = (360 / n) * i + gap / 2, a1 = (360 / n) * (i + 1) - gap / 2;
    const seg = document.createElementNS(SVG, "path");
    seg.setAttribute("d", sector(68, 108, a0, a1));
    seg.setAttribute("class", "progress-seg" + (s.done ? " done" : ""));
    seg.style.setProperty("--i", String(i));
    svg.append(seg);
    if (s.done) {
      for (const k of [0.3, 0.7]) {
        const a = a0 + (a1 - a0) * k, r = 84 + 10 * k;
        const rad = ((a - 90) * Math.PI) / 180;
        const x = 120 + r * Math.cos(rad), y = 120 + r * Math.sin(rad);
        const sp = document.createElementNS(SVG, "rect");
        for (const [k2, v] of Object.entries({ x: x - 7, y: y - 2.4, width: 14, height: 4.8, rx: 2.4, class: "progress-sprinkle", transform: `rotate(${Math.round(a * 1.7) % 180} ${x} ${y})` })) sp.setAttribute(k2, String(v));
        svg.append(sp);
      }
    }
  });
  return svg;
}

// renderNudge shows, in the sidebar, how far setup has come, until it's
// done or dismissed.
function renderNudge() {
  const s = state.setup;
  const show = !!s && isAdmin() && !s.complete && !readPrefs().setupDismissed;
  $("setup-nudge").hidden = !show;
  if (!show) return;
  clear($("setup-nudge-ring")).append(progressRing(s.steps, { size: "tiny" }));
  $("setup-nudge-count").textContent = `${s.done} of ${s.total} done`;
}

// setupCard is the Overview's reminder of what's left, which can be put
// away.
export function renderSetupCard() {
  const box = clear($("setup-card"));
  const s = state.setup;
  if (!s || !isAdmin() || s.complete || readPrefs().setupDismissed) return;
  const dismiss = h("button", { type: "button", class: "ghost icon-button", "aria-label": "Hide the setup checklist", title: "Hide" }, icon("x"));
  dismiss.addEventListener("click", () => {
    setPref("setupDismissed", true);
    renderSetupCard();
    renderNudge();
    toast("Hidden. Find it in Settings, as Setup guide.", {
      action: { label: "Undo", run: () => { setPref("setupDismissed", false); renderSetupCard(); renderNudge(); } },
    });
  });
  box.append(enter(h("section", { class: "card setup-card", "aria-labelledby": "setup-card-title" },
    progressRing(s.steps, { size: "small" }),
    h("div", { class: "setup-card-text" },
      h("h3", { id: "setup-card-title", text: "Finish setting up" }),
      h("p", { class: "muted" }, `${s.done} of ${s.total} done. Next: `, h("strong", { text: s.next.title }), ".")),
    h("a", { class: "button primary", href: routeHash("setup") }, "Continue", icon("arrow")),
    dismiss)));
}

// open is the step shown open: the one chosen, or the first not done.
let open = "";

// renderSetupView shows the checklist, each step doable in place.
export async function renderSetupView() {
  const s = await loadSetup();
  const box = $("setup");
  if (!s.steps.some((x) => x.id === open)) open = s.next?.id || "";

  const title = $("setup-title");
  title.classList.toggle("visually-hidden", false);
  title.textContent = s.complete ? "You're all set" : "Let's protect your network";

  const hero = h("div", { class: "setup-hero" },
    h("div", { class: "setup-hero-ring" }, progressRing(s.steps, { size: "large" }),
      h("div", { class: "setup-hero-count", "aria-hidden": "true" },
        s.complete ? buddy("happy") : h("span", { class: "setup-hero-figure", text: `${s.done}/${s.total}` }))),
    h("div", { class: "setup-hero-text" },
      h("p", { class: "setup-lede", text: s.complete
        ? "Every step is done. doh is quietly protecting your network, and the Overview shows what it's doing."
        : "A few steps, a few minutes. Each one checks itself off as soon as doh sees it done." }),
      h("p", { class: "muted", role: "status", text: `${s.done} of ${s.total} steps done.` })));

  const list = h("ol", { class: "setup-steps" }, s.steps.map((step, i) => stepCard(step, i, s)));
  const foot = s.complete
    ? h("p", { class: "setup-foot" }, h("a", { class: "button primary", href: routeHash("overview") }, "Go to the Overview", icon("arrow")))
    : h("p", { class: "setup-foot muted" }, "Not now? ",
      h("button", { type: "button", class: "link", text: "Hide this checklist", onClick: () => { setPref("setupDismissed", true); renderNudge(); go("overview"); } }),
      readPrefs().setupDismissed ? "" : ". It stays in Settings, as Setup guide.");
  clear(box).append(hero, list, foot);
  // The view's heading, wherever it was, leads the hero.
  title.remove();
  hero.querySelector(".setup-hero-text").prepend(title);
}

// stepCard shows one step: a header that opens it, and what to do.
function stepCard(step, i, s) {
  const isOpen = step.id === open;
  const bodyID = `step-${step.id}-body`;
  const head = h("button", { type: "button", class: "ob-head", "aria-expanded": String(isOpen), "aria-controls": bodyID },
    h("span", { class: "ob-mark", "aria-hidden": "true" }, step.done ? icon("check") : String(i + 1)),
    h("span", { class: "ob-text" },
      h("span", { class: "ob-title" }, step.title, step.done ? h("span", { class: "visually-hidden", text: ", done" }) : null),
      h("span", { class: "ob-line muted", text: step.line })),
    icon("chevron-right", "chevron"));
  head.addEventListener("click", () => {
    open = isOpen ? "" : step.id;
    renderSetupView().catch(report);
  });
  const body = h("div", { class: "ob-body", id: bodyID, hidden: !isOpen }, isOpen ? STEP_BODIES[step.id](step, s) : null);
  return h("li", { class: "ob-step" + (step.done ? " done" : "") + (isOpen ? " open" : "") }, head, body);
}

// advance re-checks the list after a step is done, celebrates it, and
// opens the next.
async function advance(id) {
  open = "";
  await renderSetupView();
  const card = [...document.querySelectorAll(".ob-step")][state.setup.steps.findIndex((x) => x.id === id)];
  if (card) burst(card.querySelector(".ob-mark"), 10);
}

const STEP_BODIES = {
  passkey(step) {
    const me = state.auth?.session;
    if (step.done) return [h("p", { text: `You're signed in as ${me?.name || "yourself"}, with a passkey. Sign-in links now need one to finish.` }),
      h("a", { class: "button", href: routeHash("settings", "account") }, "Manage passkeys", icon("arrow"))];
    const rpID = state.auth?.rp_id;
    if (rpID && location.hostname !== rpID) {
      return [h("p", { class: "hint", text: `Passkeys for this server only work at ${rpID}. Open the UI there to add one.` })];
    }
    const person = h("input", { id: "setup-person", autocomplete: "name", maxlength: 64, placeholder: "Alex", required: !me?.person });
    const name = h("input", { id: "setup-passkey-name", maxlength: 64, placeholder: "MacBook", spellcheck: "false", required: true });
    const submit = h("button", { type: "submit", class: "primary" }, icon("key"), "Add a passkey");
    const form = h("form", { class: "fields ob-form" },
      me?.person ? null : h("label", {}, "Your name", person),
      h("label", {}, "This device", name),
      submit);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (await registerPasskey(name.value.trim(), person.value.trim(), submit)) await advance("passkey");
    });
    return [h("p", { class: "muted", text: "Your device asks for your face, fingerprint, or PIN. Nothing to type next time, and nothing anyone can phish." }), form];
  },

  device(step, s) {
    const profiles = state.profiles;
    if (!profiles.length) {
      return [h("p", { text: "There are no profiles to connect a device to." }), h("a", { class: "button", href: routeHash("profiles") }, "Create a profile", icon("arrow"))];
    }
    const named = s.devices.find((d) => d.device);
    const intro = step.done
      ? h("p", {}, named ? `${named.device} is connected, to ${profiles.find((p) => p.id === named.profile)?.name || named.profile}. ` : "Devices are connected. ", "Connect another any time.")
      : h("p", { class: "muted", text: "Choose who it's for, name it, and open the link on the device. It takes a minute." });
    const first = profiles.find((p) => p.id !== "default") || profiles[0];
    let chosen = state.connect.profile && profiles.some((p) => p.id === state.connect.profile) ? state.connect.profile : first.id;
    const pick = h("select", { id: "setup-profile" }, profiles.map((p) => h("option", { value: p.id, text: p.name || p.id })));
    pick.value = chosen;
    const device = deviceField();
    const flow = h("div", {});
    const draw = () => {
      const p = profiles.find((x) => x.id === chosen);
      clear(flow).append(setupLinkFlow(p, device.value, { onConnected: () => setTimeout(() => advance("device").catch(report), 2400) }));
    };
    pick.addEventListener("change", () => { chosen = state.connect.profile = pick.value; draw(); });
    draw();
    return [intro,
      h("div", { class: "fields ob-form" }, h("label", { class: "device-name" }, h("span", { text: "Profile" }), pick), device.row),
      flow];
  },

  alerts(step, s) {
    if (step.done) {
      return [h("p", { text: `Alerts go to ${s.destinations.map((d) => d.name || d.url).join(", ")}.` }),
        h("a", { class: "button", href: routeHash("settings", "alerts") }, "Alert settings", icon("arrow"))];
    }
    const add = (type) => {
      document.addEventListener("doh:alerts-changed", () => advance("alerts").catch(report), { once: true });
      openAddDestination(type);
    };
    const push = pushSupported();
    const notify = (e) => {
      document.addEventListener("doh:alerts-changed", () => advance("alerts").catch(report), { once: true });
      notifyThisBrowser(e.currentTarget);
    };
    return [
      h("p", { class: "muted", text: push
        ? "Get alerts as notifications in this browser, or on your phone with the free ntfy app. Threats come through at once; new devices and failing lookups, too, outside quiet hours."
        : "With the free ntfy app, alerts arrive on your phone. Threats come through at once; new devices and failing lookups, too, outside quiet hours." }),
      h("div", { class: "row-actions" },
        push ? h("button", { type: "button", class: "primary", onClick: notify }, icon("bell"), "Notify this browser") : null,
        h("button", { type: "button", class: push ? "" : "primary", onClick: () => add("ntfy") }, push ? null : icon("bell"), "Add ntfy"),
        h("button", { type: "button", onClick: () => add("webhook") }, "Add a webhook")),
    ];
  },

  network(step, s) {
    const body = [];
    const addrs = h("div", { class: "dns-addrs" }, h("p", { class: "muted", text: "Looking up doh's address…" }));
    const target = state.profiles.find((p) => p.id === "default") || state.profiles[0];
    if (target) {
      api("GET", `/profiles/${encodeURIComponent(target.id)}/setup`).then((setup) => {
        const list = (setup.dns_addrs || []);
        clear(addrs).append(list.length
          ? h("dl", { class: "endpoints" }, h("dt", { text: "doh's address" }), h("dd", {}, h("code", { text: list.join(", ") }), copyButton(list[0], "doh's address")))
          : h("p", { class: "hint", text: "This server doesn't answer plain DNS yet, which routers hand out. Start it with --dns-listen :53." }));
      }).catch(() => clear(addrs));
    }
    body.push(
      h("p", { text: "Your router tells every device that joins your Wi-Fi which DNS server to use. Point it at doh, and they're all protected, even ones you can't set up, like TVs and game consoles." }),
      addrs,
      h("ol", { class: "steps" },
        h("li", { text: "Open your router's settings: its app (such as eero, Google Home, Orbi, or Deco), or the page at its address, often 192.168.0.1 or 192.168.1.1, printed on the router." }),
        h("li", { text: "Find the DHCP or LAN settings, sometimes under Advanced or Network, and the DNS server fields there. Not the internet (WAN) DNS: that's what the router itself uses." }),
        h("li", { text: "Set the primary DNS server to doh's address. Leave the secondary empty, or set it to doh too: devices use whichever they're given, and a second one that isn't doh lets them skip it." }),
        h("li", { text: "Save, then turn Wi-Fi off and on on a device, so it picks up the change. Others follow as they reconnect, within a day." })),
      h("details", { class: "fine-tune" },
        h("summary", {}, h("span", { text: "The router won't let me change DNS" })),
        h("p", { class: "muted", text: "Some internet providers' routers don't. Turn off DHCP on the router instead, and run a DHCP server beside doh, such as dnsmasq on the same machine; doh reads its leases with --dhcp-leases to name your devices. Or set each device up with a setup link." })));

    const seen = plainDNSClients(s.devices);
    const names = new Map(s.devices.map((d) => [d.client, d.hostname || d.device]));
    const since = s.since ? new Intl.DateTimeFormat(undefined, { weekday: "short", hour: "numeric", minute: "2-digit" }).format(new Date(s.since)) : "";
    const verify = h("div", { class: "verify", role: "status" },
      h("h4", { text: "Check it worked" }),
      seen.length
        ? h("p", {}, `doh has answered ${plural(seen.length, "device")} over plain DNS${since ? ` since ${since}` : ""}: `,
          h("span", { class: "mono", text: seen.slice(0, 6).map((c) => names.get(c) || c).join(", ") }), seen.length > 6 ? "…" : "", ".",
          seen.length >= ROUTER_SEEN ? " That's what a router sending devices here looks like." : " Once a second device appears, this step checks itself off.")
        : h("p", { class: "muted", text: "No device has asked doh over plain DNS yet. After you change the router, reconnect a device, then check again." }),
      h("div", { class: "row-actions" },
        h("button", { type: "button", onClick: () => renderSetupView().catch(report) }, "Check again"),
        step.done ? null : h("button", { type: "button", class: "ghost", onClick: () => { setPref("networkDone", true); advance("network").catch(report); } }, "I've done this")));
    body.push(verify);
    return body;
  },
};

