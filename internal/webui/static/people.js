import { api, APIError, authCall, report } from "./api.js";
import { syncTheme } from "./commands.js";
import { $, badge, clear, confirmDialog, copyButton, emptyState, fmtTime, h, icon, toast } from "./dom.js";
import { enter } from "./motion.js";
import { passkeyError, refreshAuth, showSignIn, signOut } from "./session.js";
import { refreshSettings } from "./settings.js";
import { isAdmin, isOperator, state, tenantName } from "./state.js";
import { applyTheme, currentTheme, themeLabel } from "./theme.js";
import { webauthnJSON } from "./webauthn.js";

// renderAccountPanel shows who's signed in, adds passkeys, lists their
// own, and chooses the theme.
export async function renderAccountPanel() {
  const me = state.auth?.session;
  $("add-passkey-person").hidden = !!me?.person;
  $("ap-person").required = !me?.person;

  const host = $("security-host");
  const rpID = state.auth?.rp_id;
  host.hidden = !rpID || location.hostname === rpID;
  host.textContent = host.hidden ? "" : `Passkeys for this server only work at ${rpID}. Open the UI there to add one.`;

  const role = [me?.role === "reader" ? "Reader" : "Admin", state.status?.tenant ? tenantName(state.status.tenant) : isOperator() ? "Operator" : ""].filter(Boolean).join(" · ");
  clear($("account-who")).append(
    h("span", { class: "avatar big", "aria-hidden": "true" }, me?.person ? (me.name.match(/\p{L}|\p{N}/u)?.[0] || "?").toUpperCase() : icon("key")),
    h("div", {},
      h("p", { class: "account-name", text: me?.person ? me.name : "Signed in with a link" }),
      h("p", { class: "muted", text: me?.person ? role : `${role}. Add a passkey to be someone here.` })),
    h("button", { type: "button", class: "ghost", onClick: () => signOut() }, icon("signout"), "Sign out"));

  renderThemeChoice();
  const box = clear($("my-passkeys"));
  if (!me?.person) return;
  const data = await api("GET", "/people");
  const mine = (data?.people || []).find((p) => p.id === me.person);
  if (mine?.passkeys?.length) {
    box.append(h("div", { class: "section" }, h("h4", { text: "Your passkeys" }), passkeyList(mine, true)));
  }
}

// renderThemeChoice offers the themes as a segmented choice.
function renderThemeChoice() {
  const box = clear($("theme-choice"));
  for (const t of ["system", "light", "dark"]) {
    const input = h("input", { type: "radio", name: "theme-choice", value: t, checked: currentTheme() === t });
    input.addEventListener("change", () => { applyTheme(t); syncTheme(); });
    box.append(h("label", {}, input, h("span", {}, icon({ system: "system", light: "sun", dark: "moon" }[t]), themeLabel(t))));
  }
}

// renderPeoplePanel lists who can sign in, and invites more.
export async function renderPeoplePanel() {
  const me = state.auth?.session;
  const invite = clear($("people-invite"));
  if (isAdmin()) invite.append(inviteCard());
  const data = await api("GET", "/people");
  const people = data?.people || [];
  state.hints.people = people.length;
  renderPeople(people, me);
}

// inviteCard makes single-use sign-in links for someone else in the
// household, as an admin or read-only.
function inviteCard() {
  const result = h("div", { "aria-live": "polite" });
  const role = h("select", { "aria-label": "Their access" },
    h("option", { value: "admin", text: "Admin: can change things" }),
    h("option", { value: "reader", text: "Read-only: can look" }));
  const button = h("button", { type: "button", class: "primary" }, icon("link"), "Make an invite link");
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      const link = await api("POST", "/signin-links", { body: { role: role.value } });
      clear(result).append(enter(h("div", { class: "invite" },
        h("div", { class: "link" }, h("output", { text: link.url }), copyButton(link.url, "invite link")),
        h("p", { class: "field-note", text: `Send it to them privately. It works once, until ${fmtTime(link.expires)}.${link.passkey_required ? " They'll finish with a passkey they already have." : " Once in, they add a passkey of their own."}` }))));
    } catch (err) {
      report(err);
    } finally {
      button.disabled = false;
    }
  });
  return h("div", { class: "card invite-card" },
    h("div", { class: "add-passkey-intro" },
      h("span", { class: "id-badge", "aria-hidden": "true" }, icon("people")),
      h("div", {}, h("h4", { text: "Invite someone" }),
        h("p", { class: "muted", text: "A single-use link that signs them in. They add a passkey, and from then on it's theirs." }))),
    h("div", { class: "invite-form" }, role, button), result);
}

// passkeyList lists a person's passkeys, each removable by admins.
function passkeyList(person, mine) {
  return h("ul", { class: "passkeys" }, person.passkeys.map((k) => h("li", { class: "passkey" },
    h("div", { class: "passkey-name" }, k.name, k.synced ? h("span", { class: "badge synced", text: "Synced", title: "A multi-device passkey, backed up to the person's account" }) : null),
    h("div", { class: "muted passkey-meta", text: `Added ${fmtTime(k.created, true)} · ${k.last_used ? "last used " + fmtTime(k.last_used, true) : "never used"}` }),
    isAdmin() ? h("button", { type: "button", class: "ghost danger-text", text: "Remove", "aria-label": `Remove passkey ${k.name}`, onClick: () => removePasskey(person, k, mine) }) : null,
  )));
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
    box.append(emptyState({
      title: "No one has a passkey yet.",
      body: "Until someone adds one, sign-in links from doh ui sign in on their own. Add yours in Account & passkeys.",
      action: h("a", { class: "button", href: "#/settings/account" }, icon("key"), "Add a passkey"),
      compact: true,
    }));
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
    return h("article", { class: "card person" }, head, passkeyList(person, mine));
  });
}


// describeActor names who made something, from the server's record of
// it: a person by name, or how someone signed in.
export function describeActor(by, people) {
  const person = people.find((p) => p.id === by);
  if (person) return person.name;
  return { "admin token": "the admin token", "reader token": "the reader token", "sign-in link": "a sign-in link" }[by] || "someone no longer here";
}

// addPasskey creates a passkey for the signed-in person, or for a link
// session, for a new person.
// registerPasskey creates a passkey named name for the signed-in person,
// or, for a link session, for a new person named person. It returns
// whether it did, having said why not if it didn't.
export async function registerPasskey(name, person, button) {
  button.disabled = true;
  try {
    const begin = await authCall("POST", "/passkey/register", { name, person });
    const credential = await navigator.credentials.create({ publicKey: webauthnJSON.creationOptions(begin.options.publicKey) });
    const passkey = await authCall("POST", `/passkey/register/${encodeURIComponent(begin.id)}`, JSON.stringify(webauthnJSON.credential(credential)));
    toast(`Added passkey ${passkey.name}.`);
    await refreshAuth();
    return true;
  } catch (err) {
    if (err instanceof APIError && err.status === 401) showSignIn("Your session ended. Sign in again.");
    else toast(passkeyError(err), { error: true });
    return false;
  } finally {
    button.disabled = false;
  }
}

// addPasskey adds a passkey from the Account form.
export async function addPasskey(e) {
  e.preventDefault();
  if (await registerPasskey($("ap-name").value.trim(), $("ap-person").value.trim(), $("ap-submit"))) {
    $("ap-name").value = "";
    await refreshSettings();
  }
}

export async function removePasskey(person, passkey, mine) {
  const last = person.passkeys.length === 1;
  const warning = mine && last ? " It's your last passkey: you'll need a sign-in link to sign in again." : "";
  if (!(await confirmDialog(`Remove passkey ${passkey.name}?`, `It will no longer sign ${person.name} in.${warning}`))) return;
  try {
    await api("DELETE", `/people/${encodeURIComponent(person.id)}/passkeys/${encodeURIComponent(passkey.id)}`);
    toast(`Removed passkey ${passkey.name}.`);
    await refreshSettings();
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
    await refreshSettings();
  } catch (err) {
    report(err);
  }
}

