import { api, report } from "./api.js";
import { $, h, count, badge, clear, edit, toast, fmtTime, confirmDialog, copyButton } from "./dom.js";
import { section, chipEditor } from "./profiles.js";
import { loadTenants, loadPolicy } from "./session.js";
import { state } from "./state.js";

// renderTenants lists tenants for the operator, each editable in place.
export async function renderTenants() {
  await Promise.all([loadTenants(), loadPolicy()]);
  const box = clear($("tenant-cards"));
  if (!state.tenants.length) {
    box.append(h("p", { class: "muted", text: "No tenants yet. Create one to share this server with another household." }));
    return;
  }
  for (const t of state.tenants) box.append(tenantCard(t));
}

// patchTenant applies a merge patch to a tenant, re-rendering the view.
export async function patchTenant(id, patch) {
  const t = await api("PATCH", `/tenants/${encodeURIComponent(id)}`, { body: patch, patch: true });
  const i = state.tenants.findIndex((x) => x.id === id);
  if (i >= 0) state.tenants[i] = t;
  await renderTenants();
  return t;
}

export function tenantCard(t) {
  const profiles = state.profiles.filter((p) => p.tenant === t.id);
  const networks = t.networks || [];

  const custom = edit(h("input", { type: "checkbox", role: "switch", checked: !!t.custom_lists, "aria-label": `Custom lists for ${t.id}` }));
  custom.addEventListener("change", () => patchTenant(t.id, { custom_lists: custom.checked }).catch((err) => { custom.checked = !custom.checked; report(err); }));

  const max = edit(h("input", { type: "number", min: 1, max: 1000, value: t.max_profiles || 20, "aria-label": `Most profiles for ${t.id}` }));
  max.addEventListener("change", () => {
    const n = parseInt(max.value, 10);
    if (n >= 1) patchTenant(t.id, { max_profiles: n }).catch(report);
  });

  const summary = [count(profiles.length, "profile"), networks.length ? count(networks.length, "network") : "no networks", t.custom_lists ? "custom lists allowed" : null].filter(Boolean).join(" · ");
  const head = h("div", { class: "tenant-head" },
    badge(t.name || t.id),
    h("div", { class: "tenant-title" },
      h("h3", {}, t.name || t.id, " ", h("span", { class: "muted mono", text: t.id })),
      h("p", { class: "muted", text: summary })),
    h("span", { class: "spacer" }),
    edit(h("button", { type: "button", class: "ghost danger-text", text: "Delete", onClick: () => deleteTenant(t, profiles.length) })),
  );

  return h("article", { class: "card tenant-card" },
    head,
    h("div", { class: "tenant-grid" },
      section("Networks", "Addresses its profiles may select devices by.",
        chipEditor(networks, "192.168.10.0/24", `Network for ${t.id}`,
          (v) => patchTenant(t.id, { networks: [...networks, v] }),
          (v) => patchTenant(t.id, { networks: networks.filter((n) => n !== v) }))),
      section("Profiles", "",
        profiles.length
          ? h("div", { class: "chips" }, profiles.map((p) => h("span", { class: "chip", text: p.id })))
          : h("p", { class: "muted", text: "None yet. Its admins create them, or you can from Profiles." })),
      section("Limits", "",
        h("div", { class: "toggle-list" },
          h("div", { class: "toggle" }, h("div", { class: "title", text: "Custom lists" }), h("div", { class: "control" }, custom),
            h("div", { class: "desc", text: "Let its profiles use blocklists by HTTPS URL, which this server downloads, not only presets." })),
          h("div", { class: "toggle" }, h("div", { class: "title", text: "Most profiles" }), h("div", { class: "control" }, max),
            h("div", { class: "desc", text: `It has ${profiles.length}.` })),
        )),
    ),
    inviteSection(t),
  );
}

// inviteSection makes single-use sign-in links for a tenant's people.
export function inviteSection(t) {
  const result = h("div", { "aria-live": "polite" });
  const role = edit(h("select", { "aria-label": "Role" },
    h("option", { value: "admin", text: "Admin" }),
    h("option", { value: "reader", text: "Read-only" })));
  const button = edit(h("button", { type: "button", class: "primary", text: "Invite someone" }));
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      const link = await api("POST", "/signin-links", { body: { tenant: t.id, role: role.value } });
      clear(result).append(h("div", { class: "invite" },
        h("div", { class: "link" }, h("output", { text: link.url }), copyButton(link.url, "sign-in link")),
        h("p", { class: "field-note", text: `Send this to them. It works once, and expires at ${fmtTime(link.expires)}.${link.passkey_required ? " They'll finish with their passkey." : " They can add a passkey once signed in."}` }),
      ));
    } catch (err) {
      report(err);
    } finally {
      button.disabled = state.readOnly;
    }
  });
  return section("Invite", "A single-use sign-in link to this tenant, for its first admin or anyone else.",
    h("div", { class: "invite-form" }, role, button), result);
}

export async function deleteTenant(t, profiles) {
  const text = profiles
    ? `It still has ${profiles} profile${profiles === 1 ? "" : "s"}: delete or move them first.`
    : "Its people and their passkeys are removed too, and they're signed out.";
  if (!(await confirmDialog(`Delete ${t.name || t.id}?`, text))) return;
  try {
    await api("DELETE", `/tenants/${encodeURIComponent(t.id)}`);
    toast(`Deleted ${t.id}`);
    await renderTenants();
  } catch (err) {
    report(err);
  }
}

export function openCreateTenant() {
  for (const id of ["t-id", "t-name", "t-networks"]) $(id).value = "";
  $("tenant-dialog").showModal();
}

export async function createTenant(e) {
  e.preventDefault();
  const body = {
    id: $("t-id").value.trim(),
    name: $("t-name").value.trim() || undefined,
    networks: $("t-networks").value.split(/[\s,]+/).filter(Boolean),
  };
  try {
    const t = await api("POST", "/tenants", { body });
    $("tenant-dialog").close();
    toast(`Created ${t.id}. Invite its first admin below.`);
    await renderTenants();
  } catch (err) {
    report(err);
  }
}

// ---------- security ----------
