import { PRESETS, matchPreset, presetPatch, undoPatch } from "./presets.js";
import { api, report } from "./api.js";
import { appsSection, schedulesSection } from "./apps.js";
import { connectSection } from "./connect.js";
import { $, h, count, icon, clear, edit, toast, fmtNum, confirmDialog } from "./dom.js";
import { go, setRoute } from "./router.js";
import { fillProfileSelects } from "./session.js";
import { state, isOperator, tenantOf, tenantName, profile, replaceProfile } from "./state.js";

export function renderProfiles() {
  const cards = clear($("profile-cards"));
  for (const p of state.profiles) {
    const name = p.name || p.id;
    const initial = (name.match(/\p{L}|\p{N}/u)?.[0] || "?").toUpperCase();
    cards.append(
      h("button", { type: "button", class: "card profile-card", "aria-pressed": String(p.id === state.selected), onClick: () => selectProfile(p.id) },
        h("span", { class: "profile-initial", "aria-hidden": "true", text: initial }),
        h("span", { class: "profile-card-body" },
          h("span", { class: "profile-card-name" }, name, isOperator() && p.tenant ? h("span", { class: "badge tenant", text: tenantName(p.tenant) }) : null),
          h("span", { class: "profile-meta", text: profileSummary(p) }),
          p.name ? h("span", { class: "profile-meta mono", text: p.id }) : null,
        ),
      ),
    );
  }
  if (!state.profiles.length) cards.append(h("p", { class: "muted", text: "No profiles: every client is refused. Create a profile named \"default\" to serve everyone else." }));
  renderEditor();
}

export function selectProfile(id) {
  go("profiles", state.selected === id ? "" : id);
  if (state.selected) requestAnimationFrame(() => $("profile-editor").scrollIntoView({ behavior: "smooth", block: "start" }));
}

// patchProfile applies a merge patch, re-rendering on success or failure.
export async function patchProfile(id, patch) {
  try {
    const p = await api("PATCH", `/profiles/${encodeURIComponent(id)}`, { body: patch, patch: true });
    replaceProfile(p);
    return true;
  } catch (err) {
    report(err);
    return false;
  } finally {
    renderProfiles();
  }
}

export async function domainAction(id, kind, domain, remove) {
  const path = `/profiles/${encodeURIComponent(id)}/${kind}` + (remove ? `/${encodeURIComponent(domain)}` : "");
  const p = await api(remove ? "DELETE" : "POST", path, remove ? {} : { body: { domain } });
  replaceProfile(p);
  return p;
}

export function section(title, hint, ...body) {
  return h("div", { class: "section" }, h("h3", { text: title }), hint && h("p", { class: "muted hint", text: hint }), ...body);
}

// switchControl renders a switch that applies makePatch(on) immediately.
export function switchControl(label, checked, makePatch) {
  const input = edit(h("input", { type: "checkbox", role: "switch", checked, "aria-label": label }));
  input.addEventListener("change", async () => {
    input.disabled = true;
    const ok = await patchProfile(state.selected, makePatch(input.checked));
    if (!ok) input.checked = !input.checked;
  });
  return input;
}

// toggleRow renders a titled, described switch that applies a patch
// immediately.
export function toggleRow(title, desc, checked, makePatch, extra) {
  const input = switchControl(title, checked, makePatch);
  return h("div", { class: "toggle" },
    h("div", { class: "title", text: title }),
    h("div", { class: "control" }, extra, input),
    h("div", { class: "desc", text: desc }),
  );
}

// chipEditor edits a list of strings, calling add and remove.
export function chipEditor(values, placeholder, label, add, remove) {
  const chips = h("div", { class: "chips" });
  for (const v of values || []) {
    chips.append(h("span", { class: "chip" }, v, edit(h("button", { type: "button", "aria-label": `Remove ${v}`, text: "✕", onClick: () => remove(v).catch(report) }))));
  }
  if (!values?.length) chips.append(h("span", { class: "muted", text: "None." }));
  const input = edit(h("input", { placeholder, "aria-label": label, spellcheck: "false" }));
  const form = h("form", { class: "chip-form" }, input, edit(h("button", { type: "submit", text: "Add" })));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const v = input.value.trim();
    if (v) add(v).then(() => toast(`Added ${v}`)).catch(report);
  });
  return h("div", {}, chips, form);
}

// ---------- connecting devices ----------

// PROFILE_TABS are the profile editor's tabs: what each holds, and how
// many things it has turned on, for its badge.
export const PROFILE_TABS = [
  { id: "connect", title: "Connect", icon: "arrow", count: () => 0 },
  { id: "protection", title: "Protection", icon: "security", count: (p) => Object.values(p.security || {}).filter((v) => v === true).length + (p.lists || []).length + (p.safe_search ? 1 : 0) },
  { id: "apps", title: "Apps & schedules", icon: "block", count: (p) => (p.services || []).length + (p.schedules || []).length },
  { id: "rules", title: "Allow & deny", icon: "allow", count: (p) => (p.allow || []).length + (p.deny || []).length + (p.block_tlds || []).length },
  { id: "devices", title: "Devices", icon: "system", count: (p) => (p.devices || []).length + (p.clients || []).length + (p.rewrites || []).length },
  { id: "settings", title: "Settings", icon: "profiles", count: () => 0 },
];

// defaultTab is where a profile opens: how to connect a device, for one
// no device uses yet, and otherwise its protection.
export const defaultTab = (p) => (!(p.devices || []).length && !(p.clients || []).length && p.id !== "default" ? "connect" : "protection");

// profileSummary says in a line what a profile does.
export function profileSummary(p) {
  const on = Object.values(p.security || {}).filter((v) => v === true).length + (p.safe_search ? 1 : 0);
  return [
    count(on, "protection"),
    count((p.lists || []).length, "list"),
    (p.services || []).length ? `${count(p.services.length, "app")} blocked` : null,
    (p.schedules || []).length ? count(p.schedules.length, "schedule") : null,
    count((p.devices || []).length, "device"),
  ].filter(Boolean).join(" · ");
}

export function renderEditor() {
  const box = $("profile-editor");
  const p = profile();
  box.hidden = !p;
  clear(box);
  if (!p) return;

  const tab = PROFILE_TABS.some((t) => t.id === state.profileTab) ? state.profileTab : defaultTab(p);
  const card = h("div", { class: "card editor" });
  box.append(card);

  card.append(h("div", { class: "editor-head" },
    h("div", { class: "editor-title" },
      h("h2", { text: p.name || p.id }),
      h("p", { class: "muted editor-sub" },
        h("span", { class: "mono", text: p.id }),
        isOperator() && p.tenant ? h("span", { class: "badge tenant", text: tenantName(p.tenant) }) : null,
        h("span", { text: profileSummary(p) })),
    ),
  ));

  // The tabs: a tablist with arrow keys between tabs, each a URL.
  const tabs = h("div", { class: "tabs-strip", role: "tablist", "aria-label": `${p.name || p.id} settings` });
  for (const t of PROFILE_TABS) {
    const n = t.count(p);
    const b = h("button", {
      type: "button", role: "tab", id: `tab-${t.id}`, "aria-selected": String(t.id === tab), "aria-controls": "profile-panel",
      tabindex: t.id === tab ? 0 : -1, onClick: () => openTab(p.id, t.id),
    }, icon(t.icon), h("span", { text: t.title }), n ? h("span", { class: "tab-count", text: fmtNum(n), "aria-label": `, ${n} on` }) : null);
    tabs.append(b);
  }
  tabs.addEventListener("keydown", (e) => {
    const all = [...tabs.querySelectorAll("[role=tab]")];
    const i = all.indexOf(document.activeElement);
    const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: all.length - 1 }[e.key];
    if (next === undefined || i < 0) return;
    e.preventDefault();
    const t = all[(next + all.length) % all.length];
    t.focus();
    t.click();
  });
  const panel = h("div", { class: "tab-panel", id: "profile-panel", role: "tabpanel", "aria-labelledby": `tab-${tab}` });
  card.append(tabs, panel);
  panel.append(...{ connect: connectTab, protection: protectionTab, apps: appsTab, rules: rulesTab, devices: devicesTab, settings: settingsTab }[tab](p));
  requestAnimationFrame(() => tabs.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: "nearest", inline: "nearest" }));
}

// openTab shows one of a profile's tabs, in the URL too.
export function openTab(id, tab) {
  state.profileTab = tab;
  setRoute("profiles", id, { tab });
  renderEditor();
  document.getElementById(`tab-${tab}`)?.focus({ preventScroll: true });
}

export function connectTab(p) {
  return [connectSection(p)];
}

export function protectionTab(p) {
  const id = p.id;
  const sec = p.security || {};
  const feats = state.catalog.features || [];
  const featToggle = (f) => {
    const isTop = f.id === "safe_search";
    const checked = isTop ? !!p.safe_search : !!sec[f.id];
    let extra;
    if (f.id === "newly_registered" && checked) {
      const days = edit(h("input", { type: "number", min: 1, max: 365, value: sec.newly_registered_days || 30, "aria-label": "Days" }));
      days.addEventListener("change", () => {
        const n = parseInt(days.value, 10);
        if (n >= 1 && n <= 365) patchProfile(id, { security: { newly_registered_days: n } });
      });
      extra = h("label", { class: "muted" }, "younger than ", days, " days");
    }
    return toggleRow(f.title, f.description, checked, (on) => (isTop ? { safe_search: on } : { security: { [f.id]: on } }), extra);
  };
  const lists = p.lists || [];
  const presets = state.catalog.presets || [];
  const presetNames = new Set(presets.map((x) => x.name));
  const listToggle = (pr) => toggleRow(pr.title, pr.description, lists.includes(pr.name), (on) => ({
    lists: on ? [...(profile().lists || []), pr.name] : (profile().lists || []).filter((l) => l !== pr.name),
  }));
  const group = (cat) => h("div", { class: "toggle-list" }, presets.filter((x) => x.category === cat).map(listToggle));
  const custom = lists.filter((l) => !presetNames.has(l) && l !== "default");
  const current = matchPreset(p);
  const fine = h("details", { class: "fine-tune", open: current === "" },
    h("summary", {}, h("span", { text: "Fine-tune" }), h("span", { class: "muted", text: current ? "Every protection and list, one by one" : "Your own mix of protections and lists" })),
    section("Security", "Built-in protections. Changes apply to new queries at once.",
      h("div", { class: "toggle-list" }, feats.filter((f) => f.category !== "parental").map(featToggle))),
    section("Threat lists", "Blocklists of known-bad domains.", group("security")),
    section("Privacy", "Ads and trackers.", group("privacy")),
    section("Parental", "Content some households restrict.",
      h("div", { class: "toggle-list" }, feats.filter((f) => f.category === "parental").map(featToggle)), group("parental")),
  );
  return [levelSection(p, current), fine, customListsSection(p, custom, lists)];
}

// levelSection offers the protection presets as a choice of levels,
// applied at once with Undo.
export function levelSection(p, current) {
  const group = h("div", { class: "levels", role: "radiogroup", "aria-label": "Protection level" });
  for (const preset of PRESETS) {
    const on = preset.id === current;
    const b = edit(h("button", {
      type: "button", class: "level", role: "radio", "aria-checked": String(on),
      onClick: () => applyPreset(p, preset),
    },
    h("span", { class: "level-head" }, h("strong", { text: preset.name }), on ? icon("check") : null),
    h("span", { class: "level-line", text: preset.line })));
    group.append(b);
  }
  // Arrow keys move between levels, as in any radio group.
  group.addEventListener("keydown", (e) => {
    const all = [...group.querySelectorAll(".level")];
    const i = all.indexOf(document.activeElement);
    const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
    if (i < 0 || !step) return;
    e.preventDefault();
    all[(i + step + all.length) % all.length].focus();
  });
  return section("Protection level", current ? "" : "This profile has its own mix. Choose a level to start again from it.", group);
}

export async function applyPreset(p, preset) {
  const before = undoPatch(p);
  if (!(await patchProfile(p.id, presetPatch(p, preset)))) return;
  toast(`${p.name || p.id} is now at ${preset.name}.`, {
    action: { label: "Undo", run: async () => { if (await patchProfile(p.id, before)) toast("Put back as it was."); } },
  });
}

export function appsTab(p) {
  return [appsSection(p), schedulesSection(p)];
}

export function rulesTab(p) {
  const id = p.id;
  const refresh = (pp) => { renderProfiles(); return pp; };
  return [
    section("Allowed domains", "Never blocked by anything in this profile, with their subdomains.",
      chipEditor(p.allow, "example.com", "Allow domain", (v) => domainAction(id, "allow", v).then(refresh), (v) => domainAction(id, "allow", v, true).then(refresh))),
    section("Denied domains", "Always blocked, with their subdomains.",
      chipEditor(p.deny, "example.com", "Deny domain", (v) => domainAction(id, "deny", v).then(refresh), (v) => domainAction(id, "deny", v, true).then(refresh))),
    section("Blocked TLDs", "Every name under these top-level domains.",
      chipEditor(p.block_tlds, "zip", "Block TLD",
        (v) => patchProfile(id, { block_tlds: [...(p.block_tlds || []), v.replace(/^\./, "")] }),
        (v) => patchProfile(id, { block_tlds: (p.block_tlds || []).filter((t) => t !== v) }))),
  ];
}

export function devicesTab(p) {
  const id = p.id;
  const devices = p.devices || [];
  const devRows = h("div", { class: "rows" });
  for (const d of devices) {
    devRows.append(h("div", { class: "row-item" },
      h("strong", { text: d.name }), h("span", { class: "mono muted", text: (d.addrs || []).join(", ") || "DoH path only" }),
      edit(h("button", { type: "button", class: "small", text: "Remove", onClick: () => patchProfile(id, { devices: devices.filter((x) => x.name !== d.name) }) })),
    ));
  }
  if (!devices.length) devRows.append(h("span", { class: "muted", text: "No devices." }));
  const dName = edit(h("input", { placeholder: "living-room-tv", "aria-label": "Device name", spellcheck: "false" }));
  const dAddrs = edit(h("input", { placeholder: "192.168.1.50, fd00::50", "aria-label": "Device addresses", spellcheck: "false" }));
  const devForm = h("form", { class: "chip-form" }, dName, dAddrs, edit(h("button", { type: "submit", text: "Add device" })));
  devForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const n = dName.value.trim();
    if (!n) return;
    const addrs = dAddrs.value.split(/[\s,]+/).filter(Boolean);
    patchProfile(id, { devices: [...devices, { name: n, addrs }] });
  });
  const bounds = networkHint(p);

  const rewrites = p.rewrites || [];
  const rwRows = h("div", { class: "rows" });
  for (const rw of rewrites) {
    rwRows.append(h("div", { class: "row-item" },
      h("span", { class: "mono", text: rw.name }), h("span", { class: "muted", text: "→" }), h("span", { class: "mono", text: (rw.addrs || []).join(", ") }),
      edit(h("button", { type: "button", class: "small", text: "Remove", onClick: () => patchProfile(id, { rewrites: rewrites.filter((x) => x !== rw) }) })),
    ));
  }
  if (!rewrites.length) rwRows.append(h("span", { class: "muted", text: "No rewrites." }));
  const rName = edit(h("input", { placeholder: "nas.home.arpa", "aria-label": "Rewrite name", spellcheck: "false" }));
  const rAddrs = edit(h("input", { placeholder: "192.168.1.5", "aria-label": "Rewrite addresses", spellcheck: "false" }));
  const rwForm = h("form", { class: "chip-form" }, rName, rAddrs, edit(h("button", { type: "submit", text: "Add rewrite" })));
  rwForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const n = rName.value.trim();
    const addrs = rAddrs.value.split(/[\s,]+/).filter(Boolean);
    if (n && addrs.length) patchProfile(id, { rewrites: [...rewrites, { name: n, addrs }] });
  });

  return [
    section("Devices", "Named clients. Their addresses select this profile, and logs show their names.", bounds, devRows, devForm),
    section("Networks", "Addresses or prefixes whose queries use this profile. The most specific match wins.", bounds?.cloneNode(true),
      chipEditor(p.clients, "192.168.1.0/24", "Client prefix",
        (v) => patchProfile(id, { clients: [...(p.clients || []), v] }),
        (v) => patchProfile(id, { clients: (p.clients || []).filter((c) => c !== v) }))),
    section("Rewrites", "Answer names locally, such as a home server with its LAN address. Use *.domain for subdomains.", rwRows, rwForm),
  ];
}

export function settingsTab(p) {
  const id = p.id;
  const name = edit(h("input", { value: p.name || "", "aria-label": "Profile name" }));
  const nameForm = h("form", { class: "chip-form" }, name, edit(h("button", { type: "submit", text: "Rename" })));
  nameForm.addEventListener("submit", (e) => { e.preventDefault(); patchProfile(id, { name: name.value.trim() }); });

  const resp = edit(h("select", { "aria-label": "Block response" },
    h("option", { value: "nxdomain", text: "NXDOMAIN (name doesn't exist)" }),
    h("option", { value: "null", text: "Null address (0.0.0.0 and ::)" })));
  resp.value = p.block_response || "nxdomain";
  resp.addEventListener("change", () => patchProfile(id, { block_response: resp.value }));

  return [
    section("Name", "", nameForm),
    section("Behavior", "",
      h("div", { class: "toggle-list" },
        h("div", { class: "toggle" }, h("div", { class: "title", text: "Block response" }), h("div", { class: "control" }, resp), h("div", { class: "desc", text: "How blocked names are answered." })),
        toggleRow("Don't log this profile", "Keep its queries out of Activity. They're still counted in metrics.", !!p.logging?.disabled, (on) => ({ logging: { disabled: on } })),
      )),
    section("Delete this profile", p.id === "default"
      ? "Its devices fall back to other profiles. Without a default profile, clients that match no other profile are refused."
      : "Its devices fall back to other profiles, such as the default.",
    edit(h("button", { type: "button", class: "danger", text: `Delete ${p.name || p.id}`, onClick: () => deleteProfile(p) }))),
  ];
}

// ---------- apps and schedules ----------

// customListsSection edits a profile's lists by URL or path. A tenant's
// profiles may only use presets, unless the operator allows HTTPS lists,
// since the server downloads them.
export function customListsSection(p, custom, lists) {
  const id = p.id;
  const editor = (placeholder) => chipEditor(custom, placeholder, "Custom list",
    (v) => patchProfile(id, { lists: [...lists, v] }),
    (v) => patchProfile(id, { lists: lists.filter((l) => l !== v) }));

  if (!p.tenant) {
    return section("Custom lists", "Lists by URL or file path on the server, optionally named as name=location.", editor("https://example.com/list.txt"));
  }
  if (tenantOf(p.tenant)?.custom_lists) {
    return section("Custom lists", "Lists by HTTPS URL, optionally named as name=URL.", editor("https://example.com/list.txt"));
  }
  return section("Custom lists", "",
    h("p", { class: "muted", text: "This profile's tenant can use preset lists only. Ask the server's operator to allow custom lists." }),
    custom.length ? h("div", { class: "chips" }, custom.map((v) => h("span", { class: "chip", text: v }))) : null);
}

// networkHint says which addresses a tenant's profile may select devices
// by: only those within its tenant's networks.
export function networkHint(p) {
  if (!p.tenant) return null;
  const nets = tenantOf(p.tenant)?.networks || [];
  return h("p", { class: "field-note" }, nets.length
    ? `Addresses must be within this tenant's networks: ${nets.join(", ")}.`
    : "This tenant has no networks, so its devices select profiles by DoH path or host name.");
}

export async function deleteProfile(p) {
  const extra = p.id === "default" ? " Without a default profile, clients that match no other profile are refused." : "";
  if (!(await confirmDialog(`Delete ${p.name || p.id}?`, `Its devices will fall back to other profiles.${extra}`))) return;
  try {
    await api("DELETE", `/profiles/${encodeURIComponent(p.id)}`);
    state.profiles = state.profiles.filter((x) => x.id !== p.id);
    state.selected = "";
    setRoute("profiles");
    fillProfileSelects();
    renderProfiles();
    toast(`Deleted ${p.id}`);
  } catch (err) {
    report(err);
  }
}

export function openCreate() {
  $("c-id").value = "";
  $("c-name").value = "";
  const sel = $("c-tenant");
  sel.replaceChildren(sel.options[0]);
  for (const t of state.tenants) sel.append(h("option", { value: t.id, text: t.name ? `${t.name} (${t.id})` : t.id }));
  sel.value = "";
  // Tenants' profiles are always their own; only the operator chooses.
  $("c-tenant-row").hidden = !isOperator() || !state.tenants.length;
  $("create-dialog").showModal();
}

export async function createProfile(e) {
  e.preventDefault();
  const id = $("c-id").value.trim();
  const name = $("c-name").value.trim();
  try {
    const tenant = isOperator() ? $("c-tenant").value : "";
    const p = await api("POST", "/profiles", { body: { id, name, tenant: tenant || undefined, security: {} } });
    $("create-dialog").close();
    replaceProfile(p);
    state.selected = p.id;
    setRoute("profiles", p.id);
    fillProfileSelects();
    renderProfiles();
    toast(`Created ${p.id}`);
  } catch (err) {
    report(err);
  }
}

// ---------- query log ----------
