import { renderServiceAccounts } from "./accounts.js";
import { renderAlerts } from "./alerts.js";
import { APIError, api, report, authCall } from "./api.js";
import { $, h, badge, clear, toast, fmtTime, confirmDialog } from "./dom.js";
import { showSignIn, passkeyError, refreshAuth } from "./session.js";
import { state, isAdmin, isOperator, tenantName } from "./state.js";
import { webauthnJSON } from "./webauthn.js";

// renderSecurity lists who can use the admin API: people and their
// passkeys, and service accounts and their keys. The operator sees them
// grouped by tenant.
export async function renderSecurity() {
  const me = state.auth?.session;
  $("add-passkey-person").hidden = !!me?.person;
  $("ap-person").required = !me?.person;

  const host = $("security-host");
  const rpID = state.auth?.rp_id;
  host.hidden = !rpID || location.hostname === rpID;
  host.textContent = host.hidden ? "" : `Passkeys for this server only work at ${rpID}. Open the UI there to add one.`;

  const [peopleData, accountData] = await Promise.all([api("GET", "/people"), api("GET", "/service-accounts")]);
  const people = peopleData?.people || [];
  renderPeople(people, me);
  renderServiceAccounts(accountData?.service_accounts || [], people);
  await renderAlerts();
}

// byTenant groups items by their tenant, the operator's first, then
// tenants by name. It returns one group when there's nothing to tell
// apart, so a tenant's own view has no group headings.
export function byTenant(items) {
  const groups = new Map();
  for (const item of items) {
    const key = item.tenant || "";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  const keys = [...groups.keys()].sort((x, y) => (x === "" ? -1 : y === "" ? 1 : tenantName(x).localeCompare(tenantName(y))));
  return keys.map((k) => [k, groups.get(k)]);
}

// grouped renders items under their tenant's name, when the operator
// sees more than one tenant's.
export function grouped(box, items, render) {
  const groups = byTenant(items);
  const labelled = isOperator() && groups.length > 1;
  for (const [tenant, list] of groups) {
    if (labelled) box.append(h("p", { class: "group-label", text: tenant ? tenantName(tenant) : "Operator" }));
    for (const item of list) box.append(render(item));
  }
}

export function renderPeople(people, me) {
  const box = clear($("people"));
  if (!people.length) {
    box.append(h("p", { class: "muted empty", text: "No one has a passkey yet. Until someone does, sign-in links from doh ui sign in on their own." }));
    return;
  }
  grouped(box, people, (person) => {
    const mine = person.id === me?.person;
    const head = h("div", { class: "person-head" },
      badge(person.name),
      h("h4", {}, person.name, mine ? h("span", { class: "badge you", text: "You" }) : null),
      h("span", { class: "badge", text: person.role }),
      isAdmin() ? h("button", { type: "button", class: "ghost danger-text", text: "Remove", "aria-label": `Remove ${person.name}`, onClick: () => removePerson(person, mine) }) : null,
    );
    const keys = h("ul", { class: "passkeys" }, person.passkeys.map((k) => h("li", { class: "passkey" },
      h("div", { class: "passkey-name" }, k.name, k.synced ? h("span", { class: "badge synced", text: "Synced", title: "A multi-device passkey, backed up to the person's account" }) : null),
      h("div", { class: "muted passkey-meta", text: `Added ${fmtTime(k.created, true)} · ${k.last_used ? "last used " + fmtTime(k.last_used, true) : "never used"}` }),
      isAdmin() ? h("button", { type: "button", class: "ghost danger-text", text: "Remove", "aria-label": `Remove passkey ${k.name}`, onClick: () => removePasskey(person, k, mine) }) : null,
    )));
    return h("article", { class: "card person" }, head, keys);
  });
}

// ---------- service accounts ----------

// describeActor names who made something, from the server's record of
// it: a person by name, or how someone signed in.
export function describeActor(by, people) {
  const person = people.find((p) => p.id === by);
  if (person) return person.name;
  return { "admin token": "the admin token", "reader token": "the reader token", "sign-in link": "a sign-in link" }[by] || "someone no longer here";
}

// addPasskey creates a passkey for the signed-in person, or for a link
// session, for a new person.
export async function addPasskey(e) {
  e.preventDefault();
  const button = $("ap-submit");
  button.disabled = true;
  try {
    const name = $("ap-name").value.trim();
    const person = $("ap-person").value.trim();
    const begin = await authCall("POST", "/passkey/register", { name, person });
    const credential = await navigator.credentials.create({ publicKey: webauthnJSON.creationOptions(begin.options.publicKey) });
    const passkey = await authCall("POST", `/passkey/register/${encodeURIComponent(begin.id)}`, JSON.stringify(webauthnJSON.credential(credential)));
    $("ap-name").value = "";
    toast(`Added passkey ${passkey.name}.`);
    await refreshAuth();
    await renderSecurity();
  } catch (err) {
    if (err instanceof APIError && err.status === 401) showSignIn("Your session ended. Sign in again.");
    else toast(passkeyError(err), { error: true });
  } finally {
    button.disabled = false;
  }
}

export async function removePasskey(person, passkey, mine) {
  const last = person.passkeys.length === 1;
  const warning = mine && last ? " It's your last passkey: you'll need a sign-in link to sign in again." : "";
  if (!(await confirmDialog(`Remove passkey ${passkey.name}?`, `It will no longer sign ${person.name} in.${warning}`))) return;
  try {
    await api("DELETE", `/people/${encodeURIComponent(person.id)}/passkeys/${encodeURIComponent(passkey.id)}`);
    toast(`Removed passkey ${passkey.name}.`);
    await renderSecurity();
  } catch (err) {
    report(err);
  }
}

export async function removePerson(person, mine) {
  const text = mine
    ? "This removes your passkeys and signs you out everywhere."
    : `This removes their passkeys and signs them out everywhere.`;
  if (!(await confirmDialog(`Remove ${person.name}?`, text))) return;
  try {
    await api("DELETE", `/people/${encodeURIComponent(person.id)}`);
    if (mine) {
      state.auth = await authCall("GET", "/session").catch(() => state.auth);
      showSignIn("You removed yourself, and were signed out.");
      return;
    }
    toast(`Removed ${person.name}.`);
    await renderSecurity();
  } catch (err) {
    report(err);
  }
}

// ---------- alerts ----------
