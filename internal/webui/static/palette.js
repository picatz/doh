// The command palette: one place to find anything and do most things,
// by keyboard, mouse, or touch. The page supplies the commands; this
// module ranks, shows, and runs them.

// score rates how well query matches text, or returns -1 if it doesn't:
// every character of query must appear in text, in order. Matches at the
// start of words, and runs of adjacent characters, score higher, so "nsa"
// prefers "New service account" to "Unseen alarms".
export function score(query, text) {
  const q = query.trim().toLowerCase();
  if (!q) return 0;
  const t = text.toLowerCase();
  let total = 0, at = 0, run = 0;
  for (const ch of q) {
    if (ch === " ") { run = 0; continue; }
    const i = t.indexOf(ch, at);
    if (i < 0) return -1;
    const wordStart = i === 0 || /[\s\-_./(]/.test(t[i - 1]);
    run = i === at && at > 0 ? run + 1 : 0;
    total += 1 + (wordStart ? 4 : 0) + run * 2 - Math.min(i - at, 6) * 0.25;
    at = i + 1;
  }
  // Shorter texts that match as well are closer to what was meant.
  return total - t.length * 0.01;
}

// rank returns the commands matching query, best first. With no query,
// commands keep their given order.
export function rank(commands, query) {
  if (!query.trim()) return commands.filter((c) => !c.hidden);
  return commands
    .map((c) => ({ c, s: Math.max(score(query, c.title), score(query, [c.group, c.title, ...(c.keywords || [])].join(" ")) - 1) }))
    .filter(({ s }) => s >= 0)
    .sort((x, y) => y.s - x.s)
    .map(({ c }) => c);
}

// A command is { id, title, group, icon?, hint?, keywords?, shortcut?,
// hidden?, run() }. hidden commands appear only when searched for.

// Palette drives the palette dialog. provide(query) returns the commands
// to choose from, which may depend on the query, such as actions for a
// domain someone has typed.
export class Palette {
  constructor(dialog, provide, render) {
    this.dialog = dialog;
    this.input = dialog.querySelector("input");
    this.list = dialog.querySelector("[role=listbox]");
    this.provide = provide;
    this.render = render;
    this.items = [];
    this.active = 0;

    this.input.addEventListener("input", () => this.update());
    this.input.addEventListener("keydown", (e) => this.key(e));
    this.list.addEventListener("click", (e) => {
      const li = e.target.closest("[role=option]");
      if (li) this.run(Number(li.dataset.index));
    });
    this.list.addEventListener("pointermove", (e) => {
      const li = e.target.closest("[role=option]");
      if (li && Number(li.dataset.index) !== this.active) this.select(Number(li.dataset.index), false);
    });
    // A click on the backdrop closes it.
    dialog.addEventListener("click", (e) => { if (e.target === dialog) this.close(); });
  }

  open(query = "") {
    if (this.dialog.open) { this.input.select(); return; }
    this.input.value = query;
    this.update();
    this.dialog.showModal();
    this.input.focus();
    this.input.select();
  }

  close() { if (this.dialog.open) this.dialog.close(); }

  update() {
    this.items = rank(this.provide(this.input.value), this.input.value).slice(0, 50);
    this.active = 0;
    this.list.replaceChildren(...this.items.map((c, i) => {
      const li = this.render(c, this.input.value);
      li.id = `palette-option-${i}`;
      li.dataset.index = String(i);
      li.setAttribute("role", "option");
      return li;
    }));
    // Group headings: shown before the first command of each group.
    let group = "";
    for (const li of this.list.children) {
      const g = this.items[Number(li.dataset.index)].group;
      li.toggleAttribute("data-group-start", g !== group);
      if (g !== group) li.dataset.group = g;
      group = g;
    }
    this.list.hidden = !this.items.length;
    this.dialog.querySelector("[data-palette-empty]")?.toggleAttribute("hidden", this.items.length > 0);
    this.select(0, true);
  }

  select(i, scroll) {
    if (!this.items.length) { this.input.removeAttribute("aria-activedescendant"); return; }
    this.active = (i + this.items.length) % this.items.length;
    for (const li of this.list.children) li.setAttribute("aria-selected", String(Number(li.dataset.index) === this.active));
    const li = this.list.children[this.active];
    this.input.setAttribute("aria-activedescendant", li.id);
    if (scroll) li.scrollIntoView({ block: "nearest" });
  }

  key(e) {
    switch (e.key) {
      case "ArrowDown": e.preventDefault(); this.select(this.active + 1, true); break;
      case "ArrowUp": e.preventDefault(); this.select(this.active - 1, true); break;
      case "Home": if (e.ctrlKey || e.metaKey) { e.preventDefault(); this.select(0, true); } break;
      case "End": if (e.ctrlKey || e.metaKey) { e.preventDefault(); this.select(this.items.length - 1, true); } break;
      case "Enter": e.preventDefault(); this.run(this.active); break;
    }
  }

  run(i) {
    const c = this.items[i];
    if (!c) return;
    this.close();
    Promise.resolve(c.run()).catch((err) => this.dialog.dispatchEvent(new CustomEvent("palette-error", { detail: err })));
  }
}

// looksLikeDomain reports whether s could be a domain name someone wants
// to act on, such as "ads.example.com".
export function looksLikeDomain(s) {
  const d = s.trim().toLowerCase().replace(/\.$/, "");
  return d.length <= 253 && /^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(d);
}
