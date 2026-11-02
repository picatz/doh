import { api, report } from "./api.js";
import { appsSection, schedulesSection } from "./apps.js";
import { connectSection } from "./connect.js";
import { $, badge, clear, confirmDialog, count, edit, emptyState, fmtNum, h, icon, statusIcon, toast } from "./dom.js";
import { matchPreset, presetPatch, PRESETS, undoPatch } from "./presets.js";
import { go, setRoute } from "./router.js";
import { PROFILE_SECTIONS, routeHash } from "./routes.js";
import { fillProfileSelects } from "./session.js";
import { isOperator, profile, replaceProfile, state, tenantName, tenantOf } from "./state.js";

// renderProfiles shows the profiles as cards, or one profile's page when
// one is chosen: a list, then its detail, at every width.
export function renderProfiles() {
  const p = profile();
  $("profiles-index").hidden = !!p;
  if (p) { renderEditor(); return; }
  $("profile-editor").hidden = true;
  const cards = clear($("profile-cards"));
  for (const p of state.profiles) {
    const name = p.name || p.id;
    cards.append(
      h("a", { class: "card profile-card", href: routeHash("profiles", p.id) },
        badge(name),
        h("span", { class: "profile-card-body" },
          h("span", { class: "profile-card-name" }, name, isOperator() && p.tenant ? h("span", { class: "badge tenant", text: tenantName(p.tenant) }) : null),
          h("span", { class: "profile-meta", text: profileSummary(p) }),
          p.name ? h("span", { class: "profile-meta mono", text: p.id }) : null,
        ),
        icon("chevron-right", "chevron"),
      ),
    );
  }
  if (!state.profiles.length) {
    cards.append(emptyState({
      mood: "alert", title: "No profiles, so every device is refused.",
      body: "Create one named default to protect everyone not in another profile.",
      action: state.readOnly ? null : h("button", { type: "button", class: "primary", onClick: openCreate }, icon("plus"), "New profile"),
    }));
  }
}

export function selectProfile(id) {
  go("profiles", id);
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

// section is a titled part of a panel; with no title, only its hint.
export function section(title, hint, ...body) {
  return h("div", { class: "section" }, title ? h("h4", { text: title }) : null, hint && h("p", { class: "muted hint", text: hint }), ...body);
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
    chips.append(h("span", { class: "chip" }, v, edit(h("button", { type: "button", class: "chip-remove", "aria-label": `Remove ${v}`, onClick: () => remove(v).catch(report) }, icon("x")))));
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


// defaultTab is where a profile opens on a wide screen: how to connect a
// device, for one no device uses yet, and otherwise its protection.
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

// sectionHint says in a few words what one of a profile's sections holds,
// for the list of them.
export function sectionHint(p, id) {
  const n = (k) => (p[k] || []).length;
  const join = (...parts) => parts.filter(Boolean).join(" · ");
  switch (id) {
    case "connect": return "Setup link, QR code, or by hand";
    case "protection": {
      const level = PRESETS.find((x) => x.id === matchPreset(p));
      return join(level ? level.name : "Your own mix", count(n("lists"), "list"), p.safe_search ? "safe search" : "");
    }
    case "apps": return join(n("services") && `${count(n("services"), "app")} blocked`, n("schedules") && count(n("schedules"), "schedule")) || "Nothing blocked by name";
    case "rules": return join(n("allow") && `${fmtNum(n("allow"))} allowed`, n("deny") && `${fmtNum(n("deny"))} denied`, n("block_tlds") && count(n("block_tlds"), "TLD")) || "No exceptions";
    case "devices": return join(n("devices") && count(n("devices"), "device"), n("clients") && count(n("clients"), "network"), n("rewrites") && count(n("rewrites"), "rewrite")) || "None named yet";
    case "settings": return join(p.block_response === "null" ? "Null answers" : "NXDOMAIN", p.logging?.disabled ? "not logged" : "logged");
    default: return "";
  }
}

// renderEditor shows one profile: its sections as a list, and the chosen
// one beside it on a wide screen, or in its place, with a way back, on a
// narrow one. Which applies is the editor's own width, not the window's.
export function renderEditor() {
  const box = $("profile-editor");
  const p = profile();
  box.hidden = !p;
  clear(box);
  if (!p) return;

  const chosen = PROFILE_SECTIONS.some((t) => t.id === state.profileTab) ? state.profileTab : "";
  const tab = chosen || defaultTab(p);
  const name = p.name || p.id;
  const meta = PROFILE_SECTIONS.find((t) => t.id === tab);

  const head = h("div", { class: "editor-head" },
    h("a", { class: "back", href: routeHash("profiles") }, icon("chevron-left"), "Profiles"),
    h("div", { class: "editor-title" },
      badge(name),
      h("div", {},
        h("h2", { id: "profile-title", tabindex: -1, text: name }),
        h("p", { class: "muted editor-sub" },
          h("span", { class: "mono", text: p.id }),
          isOperator() && p.tenant ? h("span", { class: "badge tenant", text: tenantName(p.tenant) }) : null,
          h("span", { text: profileSummary(p) })))));

  const nav = h("nav", { class: "subnav profile-nav", "aria-label": `${name}: sections` },
    PROFILE_SECTIONS.map((t) => h("a", {
      class: "subnav-item", href: routeHash("profiles", p.id, { tab: t.id }),
      "aria-current": t.id === tab ? "page" : null,
    }, icon(t.icon), h("span", { class: "subnav-text" }, h("span", { text: t.title }), h("span", { class: "subnav-hint", text: sectionHint(p, t.id) })),
    icon("chevron-right", "chevron"))));

  const panel = h("section", { class: "profile-panel", "aria-labelledby": "panel-title" },
    h("a", { class: "back panel-back", href: routeHash("profiles", p.id) }, icon("chevron-left"), name),
    h("h3", { id: "panel-title", class: "panel-title", tabindex: -1, text: meta.title }),
    ...{ connect: connectTab, protection: protectionTab, apps: appsTab, rules: rulesTab, devices: devicesTab, settings: settingsTab }[tab](p));

  box.append(h("div", { class: "editor" }, head,
    h("div", { class: "editor-body", "data-open": chosen ? "" : null }, nav, panel)));
}

// openTab shows one of a profile's sections, in the URL and history too,
// so back returns to the list on a phone.
export function openTab(id, tab) {
  go("profiles", id, { tab });
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
    // On, but this server can't apply it: say so, and let it be turned off.
    if (f.unavailable) extra = h("span", { class: "status warn" }, statusIcon("warn"), "Not working here");
    return toggleRow(f.title, f.unavailable ? `${f.description} ${f.unavailable}` : f.description, checked, (on) => (isTop ? { safe_search: on } : { security: { [f.id]: on } }), extra);
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
      h("div", { class: "toggle-list" }, feats.filter((f) => f.category !== "parental" && (!f.unavailable || sec[f.id])).map(featToggle))),
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
      h("span", { class: "mono", text: rw.name }), icon("arrow", "muted"), h("span", { class: "mono", text: (rw.addrs || []).join(", ") }),
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

