import { api, report } from "./api.js";
import { $, badge, clear, confirmDialog, emptyState, h, icon, statusIcon, toast } from "./dom.js";
import { formatDate, fromNow } from "./format.js";
import { describeActor, grouped } from "./people.js";
import { refreshSettings } from "./settings.js";
import { isAdmin, isOperator, state } from "./state.js";

// soonDays is when a key's coming expiry is worth pointing out.
export const soonDays = 14;

// keyStatus describes a key's expiry in words and a symbol, never by
// color alone.
export function keyStatus(k, now = Date.now()) {
  const left = new Date(k.expires).getTime() - now;
  if (left <= 0) return h("span", { class: "status bad" }, statusIcon("block"), `Expired ${fromNow(k.expires, now)}`);
  const text = `Expires ${fromNow(k.expires, now)}`;
  if (left <= soonDays * 864e5) return h("span", { class: "status warn" }, statusIcon("warn"), text);
  return h("span", { class: "status", title: formatDate(k.expires) }, text);
}

// renderApiPanel lists service accounts and their keys.
export async function renderApiPanel() {
  const [peopleData, accountData] = await Promise.all([api("GET", "/people"), api("GET", "/service-accounts")]);
  renderServiceAccounts(accountData?.service_accounts || [], peopleData?.people || []);
}

export function renderServiceAccounts(accounts, people = []) {
  const box = clear($("service-accounts"));
  $("new-sa").hidden = !isAdmin();
  if (!accounts.length) {
    box.append(emptyState({
      title: "No service accounts yet.",
      body: "Make one for each script, home automation, or CI job that talks to this server, so each can be revoked on its own.",
      action: isAdmin() ? h("button", { type: "button", class: "primary", onClick: openCreateAccount }, icon("plus"), "New service account") : null,
      compact: true,
    }));
    state.hints.api = 0;
    return;
  }
  state.hints.api = accounts.length;
  grouped(box, accounts, (a) => {
    const now = Date.now();
    const keys = [...a.keys].sort((x, y) => new Date(y.expires) - new Date(x.expires));
    const live = keys.filter((k) => new Date(k.expires).getTime() > now).length;
    const head = h("div", { class: "person-head" },
      badge(a.name, "key"),
      h("h4", {}, a.name),
      h("span", { class: "badge", text: a.role }),
      isAdmin() ? h("button", { type: "button", class: "ghost", text: "Add key", "aria-label": `Add a key to ${a.name}`, onClick: () => addKey(a) }) : null,
      isAdmin() ? h("button", { type: "button", class: "ghost danger-text", text: "Delete", "aria-label": `Delete ${a.name}`, onClick: () => deleteAccount(a) }) : null,
    );
    const meta = h("p", { class: "muted passkey-meta account-meta" },
      h("code", { text: a.id, title: "Service account ID" }),
      ` · made ${fromNow(a.created)}${a.created_by ? " by " + describeActor(a.created_by, people) : ""}`,
      live ? "" : " · no working key");
    const list = keys.length
      ? h("ul", { class: "passkeys" }, keys.map((k) => {
        const expired = new Date(k.expires).getTime() <= now;
        return h("li", { class: "passkey" + (expired ? " expired" : "") },
          h("div", { class: "passkey-name" }, h("code", { text: k.id, title: "Key ID: the start of its secret, after doh_sa_" })),
          h("div", { class: "muted passkey-meta" }, keyStatus(k, now), ` · ${k.last_used ? "used " + fromNow(k.last_used) : "never used"}`),
          isAdmin() ? h("div", { class: "row-actions" },
            expired ? null : h("button", { type: "button", class: "ghost", text: "Rotate", "aria-label": `Rotate key ${k.id}`, onClick: () => rotateKey(a, k) }),
            h("button", { type: "button", class: "ghost danger-text", text: expired ? "Remove" : "Revoke", "aria-label": `${expired ? "Remove" : "Revoke"} key ${k.id}`, onClick: () => revokeKey(a, k, expired) }),
          ) : null,
        );
      }))
      : null;
    return h("article", { class: "card person" }, head, meta, list);
  });
}

export function openCreateAccount() {
  $("sa-name").value = "";
  $("sa-form").querySelector('input[value="reader"]').checked = true;
  $("sa-expires").value = "90";
  const sel = $("sa-tenant");
  sel.replaceChildren(sel.options[0]);
  for (const t of state.tenants) sel.append(h("option", { value: t.id, text: t.name || t.id }));
  $("sa-tenant-row").hidden = !isOperator() || !state.tenants.length;
  $("sa-dialog").showModal();
}

export async function createAccount(e) {
  e.preventDefault();
  const form = $("sa-form");
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    const body = {
      name: $("sa-name").value.trim(),
      role: form.querySelector('input[name="sa-role"]:checked').value,
    };
    if (isOperator() && $("sa-tenant").value) body.tenant = $("sa-tenant").value;
    const account = await api("POST", "/service-accounts", { body });
    const key = await api("POST", `/service-accounts/${encodeURIComponent(account.id)}/keys`, { body: { expires: daysFromNow($("sa-expires").value) } });
    $("sa-dialog").close();
    await refreshSettings();
    revealSecret(account, key);
  } catch (err) {
    report(err);
  } finally {
    submit.disabled = false;
  }
}

// daysFromNow returns the time n days from now, as the API takes it.
export const daysFromNow = (n) => new Date(Date.now() + Number(n) * 864e5).toISOString();

export async function addKey(a) {
  try {
    const key = await api("POST", `/service-accounts/${encodeURIComponent(a.id)}/keys`, { body: { expires: daysFromNow(90) } });
    await refreshSettings();
    revealSecret(a, key);
  } catch (err) {
    report(err);
  }
}

// rotating is the key the rotate dialog is for.
export let rotating = null;

export function rotateKey(a, k) {
  rotating = { a, k };
  $("rotate-title").textContent = `Rotate key ${k.id}`;
  $("rotate-grace").value = "3600";
  $("rotate-expires").value = "90";
  $("rotate-dialog").showModal();
}

export async function submitRotate(e) {
  e.preventDefault();
  if (!rotating) return;
  const { a, k } = rotating;
  const grace = Number($("rotate-grace").value);
  const body = { expires: daysFromNow($("rotate-expires").value) };
  if (grace) body.previous_expires = new Date(Date.now() + grace * 1000).toISOString();
  try {
    const key = await api("POST", `/service-accounts/${encodeURIComponent(a.id)}/keys/${encodeURIComponent(k.id)}/rotate`, { body });
    $("rotate-dialog").close();
    rotating = null;
    await refreshSettings();
    revealSecret(a, key, grace ? `Key ${k.id} keeps working ${fromNow(body.previous_expires)}.` : `Key ${k.id} no longer works.`);
  } catch (err) {
    report(err);
  }
}

export async function revokeKey(a, k, expired) {
  if (!expired && !(await confirmDialog(`Revoke key ${k.id}?`, `Anything using it to reach this server as ${a.name} stops working at once.`, "Revoke"))) return;
  try {
    await api("DELETE", `/service-accounts/${encodeURIComponent(a.id)}/keys/${encodeURIComponent(k.id)}`);
    toast(expired ? `Removed expired key ${k.id}.` : `Revoked key ${k.id}.`);
    await refreshSettings();
  } catch (err) {
    report(err);
  }
}

export async function deleteAccount(a) {
  const keys = a.keys.length === 1 ? "Its key stops" : a.keys.length ? `Its ${a.keys.length} keys stop` : "Nothing uses it yet, so nothing stops";
  if (!(await confirmDialog(`Delete ${a.name}?`, `${keys} working at once.`))) return;
  try {
    await api("DELETE", `/service-accounts/${encodeURIComponent(a.id)}`);
    toast(`Deleted ${a.name}.`);
    await refreshSettings();
  } catch (err) {
    report(err);
  }
}

// revealSecret shows a new key's secret, once. It's cleared from the page
// when the dialog closes, and Done waits until it's saved.
export function revealSecret(account, key, note = "") {
  showSecret(`New key for ${account.name}`, key.secret,
    [note, `It expires ${formatDate(key.key.expires)}. Send it as a bearer token, or to doh as DOH_TOKEN.`].filter(Boolean).join(" "));
}

// showSecret shows a secret the server returns only once.
export function showSecret(title, secret, meta) {
  const dlg = $("secret-dialog");
  $("secret-title").textContent = title;
  $("secret-value").textContent = secret;
  $("secret-meta").textContent = meta;
  $("secret-saved").checked = false;
  $("secret-done").disabled = true;
  $("secret-copy").textContent = "Copy";
  dlg.addEventListener("close", () => { $("secret-value").textContent = ""; }, { once: true });
  dlg.showModal();
  $("secret-copy").focus();
}

export async function copySecret() {
  const button = $("secret-copy");
  try {
    await navigator.clipboard.writeText($("secret-value").textContent);
    $("secret-copy-label").textContent = "Copied";
    setTimeout(() => { button.textContent = "Copy"; }, 2000);
  } catch {
    // Without clipboard access, select it for copying by hand.
    const range = document.createRange();
    range.selectNodeContents($("secret-value"));
    getSelection().removeAllRanges();
    getSelection().addRange(range);
    toast("Select and copy the key by hand.");
  }
}
