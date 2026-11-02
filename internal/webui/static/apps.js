import { WEEKDAYS, DAY_NAMES, DAY_PRESETS, clockMinutes, overnight, scheduleActive, formatDays, describeBlocks, formatPeriod } from "./schedule.js";
import { $, h, clear, edit, toast, confirmDialog } from "./dom.js";
import { patchProfile, section, switchControl, renderEditor } from "./profiles.js";
import { start } from "./session.js";
import { state, profile } from "./state.js";

export const CATEGORIES = [
  ["social", "Social"], ["messaging", "Messaging"], ["video", "Video and streaming"], ["music", "Music"],
  ["gaming", "Gaming"], ["ai", "AI chat"], ["shopping", "Shopping"], ["dating", "Dating"], ["gambling", "Gambling and betting"],
];

export const services = () => state.catalog.services || [];

export const serviceName = (id) => services().find((s) => s.id === id)?.name || id;

export const listTitle = (name) => state.catalog.presets?.find((x) => x.name === name)?.title || name;

export const blockNames = (kind, id) => (kind === "service" ? serviceName(id) : listTitle(id));

// appsSection toggles the services a profile always blocks, by category,
// with a search that narrows the catalog as you type.
export function appsSection(p) {
  const blocked = p.services || [];
  const known = new Set(services().map((s) => s.id));
  const groups = CATEGORIES.map(([cat, title]) => {
    const list = services().filter((s) => s.category === cat);
    if (!list.length) return null;
    return h("fieldset", { class: "app-group" }, h("legend", { text: title }),
      list.map((s) => h("label", { class: "app", "data-search": `${s.name} ${s.id} ${title}`.toLowerCase() },
        h("span", { class: "app-name", text: s.name }),
        switchControl(`Block ${s.name}`, blocked.includes(s.id), (on) => {
          const cur = profile().services || [];
          return { services: on ? [...cur, s.id] : cur.filter((x) => x !== s.id) };
        }),
      )));
  }).filter(Boolean);

  const grid = h("div", { class: "app-groups" }, groups);
  const none = h("p", { class: "muted", text: "No apps match.", hidden: true });
  const search = h("input", {
    type: "search", class: "app-search", placeholder: `Search ${services().length} apps`,
    "aria-label": "Search apps", value: state.appQuery || "",
  });
  const narrow = () => {
    const q = (state.appQuery = search.value.trim().toLowerCase());
    let shown = 0;
    for (const g of groups) {
      let any = false;
      for (const app of g.querySelectorAll(".app")) {
        app.hidden = q !== "" && !app.dataset.search.includes(q);
        any ||= !app.hidden;
      }
      g.hidden = !any;
      shown += any ? 1 : 0;
    }
    none.hidden = shown > 0;
  };
  search.addEventListener("input", narrow);
  narrow();

  const summary = blocked.length
    ? `Blocked: ${blocked.map(serviceName).join(", ")}.`
    : "Nothing blocked by name yet.";
  const unknown = blocked.filter((id) => !known.has(id));
  return section("Apps", "Block apps and sites by name, with the domains they use. Apps change their domains, so this is a best effort: deny any that slip through.",
    h("p", { class: "field-note", text: summary }),
    search, none, grid,
    unknown.length ? h("p", { class: "field-note", text: `Also blocked, but no longer in the catalog: ${unknown.join(", ")}.` }) : null);
}

// schedulesSection lists a profile's schedules, marks those in effect
// now, and adds, edits, and deletes them.
export function schedulesSection(p) {
  const id = p.id;
  const schedules = p.schedules || [];
  if (state.draft && state.draft.profile !== id) state.draft = null;

  const now = new Date();
  const rows = h("div", { class: "schedules" });
  for (const sc of schedules) {
    const active = scheduleActive(sc, now, p.time_zone);
    rows.append(h("div", { class: "schedule" + (active ? " active" : "") },
      h("div", { class: "schedule-head" },
        h("strong", { text: sc.name }),
        active ? h("span", { class: "badge active", text: "Active now" }) : null,
      ),
      h("div", { class: "schedule-when" },
        `${formatDays(sc.days)} · ${formatPeriod(sc)}`,
        overnight(sc) ? h("span", { class: "muted", text: " next morning" }) : null),
      h("div", { class: "muted", text: `Blocks ${describeBlocks(sc, blockNames)}` }),
      h("div", { class: "schedule-actions" },
        edit(h("button", { type: "button", class: "small", text: "Edit", "aria-label": `Edit ${sc.name}`, onClick: () => { state.draft = draftFrom(id, sc); renderEditor(); focusDraft(); } })),
        edit(h("button", { type: "button", class: "small danger-text", text: "Delete", "aria-label": `Delete ${sc.name}`, onClick: () => deleteSchedule(p, sc) })),
      ),
    ));
  }
  if (!schedules.length) rows.append(h("span", { class: "muted", text: "No schedules." }));

  const notes = [];
  if (schedules.length && !p.time_zone) notes.push(h("p", { class: "field-note", text: "Set a time zone to see which schedules are in effect now." }));

  const body = state.draft
    ? scheduleForm(p, state.draft)
    : edit(h("button", { type: "button", text: "Add schedule", onClick: () => { state.draft = draftFrom(id); renderEditor(); focusDraft(); } }));
  return section("Schedules", "Block more at certain times, such as games during homework or everything but school sites at bedtime.",
    timeZoneField(p), rows, ...notes, body);
}

// draftFrom starts a schedule draft for profile id, from sc when editing.
export function draftFrom(id, sc) {
  return {
    profile: id,
    editing: sc?.name ?? null,
    name: sc?.name || "",
    days: sc?.days?.length ? [...sc.days] : [...WEEKDAYS],
    start: sc?.start || "21:00",
    end: sc?.end || "07:00",
    blockAll: sc ? !!sc.block_all : true,
    allow: [...(sc?.allow || [])],
    services: [...(sc?.services || [])],
    lists: [...(sc?.lists || [])],
    deny: [...(sc?.deny || [])],
  };
}

export function focusDraft() {
  $("sc-name")?.focus();
}

// draftSchedule turns a draft into a schedule as the API takes it, or
// returns the problems with it.
export function draftSchedule(d, existing) {
  const errors = [];
  const name = d.name.trim();
  if (!name) errors.push("Name the schedule, such as Bedtime.");
  else if (existing.some((s) => s.name.toLowerCase() === name.toLowerCase() && s.name !== d.editing)) errors.push(`There's already a schedule named ${name}.`);
  if (!d.days.length) errors.push("Choose at least one day.");
  const start = clockMinutes(d.start);
  const end = clockMinutes(d.end);
  if (Number.isNaN(start) || Number.isNaN(end)) errors.push("Choose a start and end time.");
  if (!d.blockAll && !d.services.length && !d.lists.length && !d.deny.length) errors.push("Choose something to block.");
  if (errors.length) return { errors };

  const sc = { name, start: d.start, end: d.end };
  if (d.days.length < 7) sc.days = WEEKDAYS.filter((x) => d.days.includes(x));
  if (d.blockAll) {
    sc.block_all = true;
    if (d.allow.length) sc.allow = d.allow;
  } else {
    for (const k of ["services", "lists", "deny"]) if (d[k].length) sc[k] = d[k];
  }
  return { schedule: sc };
}

// scheduleForm edits the draft d, which outlives re-renders.
export function scheduleForm(p, d) {
  const errors = h("div", { class: "field-error", role: "alert" });
  const name = edit(h("input", { id: "sc-name", value: d.name, placeholder: "Bedtime", maxlength: 64, autocomplete: "off" }));
  name.addEventListener("input", () => { d.name = name.value; });

  // Days: a chip per day, and presets.
  const days = h("div", { class: "day-chips", role: "group", "aria-label": "Days" });
  const renderDays = () => {
    clear(days);
    WEEKDAYS.forEach((day, i) => {
      days.append(edit(h("button", {
        type: "button", class: "day", text: DAY_NAMES[i][0], title: DAY_NAMES[i],
        "aria-label": DAY_NAMES[i], "aria-pressed": String(d.days.includes(day)),
        onClick: () => {
          d.days = d.days.includes(day) ? d.days.filter((x) => x !== day) : WEEKDAYS.filter((x) => x === day || d.days.includes(x));
          renderDays();
        },
      })));
    });
    for (const [label, set] of DAY_PRESETS) {
      const on = set.length === d.days.length && set.every((x) => d.days.includes(x));
      days.append(edit(h("button", { type: "button", class: "small preset", text: label, "aria-pressed": String(on), onClick: () => { d.days = [...set]; renderDays(); } })));
    }
  };
  renderDays();

  // Times, with a note when the period runs past midnight.
  const start = edit(h("input", { type: "time", id: "sc-start", value: d.start, required: true }));
  const end = edit(h("input", { type: "time", id: "sc-end", value: d.end, required: true }));
  const night = h("p", { class: "field-note", "aria-live": "polite" });
  const renderNight = () => {
    const start = clockMinutes(d.start), end = clockMinutes(d.end);
    night.textContent = end === start ? "Lasts all day." : end < start ? "Runs past midnight into the next morning." : "";
  };
  start.addEventListener("input", () => { d.start = start.value; renderNight(); });
  end.addEventListener("input", () => { d.end = end.value; renderNight(); });
  renderNight();

  // What it blocks: everything but some sites, or some apps and lists.
  const mode = h("div", { class: "mode-panel" });
  const radio = (value, label) => {
    const input = edit(h("input", { type: "radio", name: "sc-mode", value, checked: d.blockAll === (value === "all") }));
    input.addEventListener("change", () => { d.blockAll = value === "all"; renderMode(); });
    return h("label", { class: "radio" }, input, label);
  };
  const renderMode = () => {
    clear(mode);
    if (d.blockAll) {
      mode.append(
        h("p", { class: "field-note", text: "The profile's allowed domains and names on your network keep working." }),
        draftChips(d.allow, "school.example", "Allow during this schedule"));
      return;
    }
    const checks = (kind, items) => h("div", { class: "check-grid" + (items.length > 24 ? " scroll" : "") }, items.map(([value, label]) => {
      const input = edit(h("input", { type: "checkbox", checked: d[kind].includes(value) }));
      input.addEventListener("change", () => { d[kind] = input.checked ? [...d[kind], value] : d[kind].filter((x) => x !== value); });
      return h("label", { class: "check" }, input, label);
    }));
    mode.append(
      h("fieldset", { class: "sub" }, h("legend", { text: "Apps" }), checks("services", services().map((s) => [s.id, s.name]))),
      h("fieldset", { class: "sub" }, h("legend", { text: "Lists" }), checks("lists", (state.catalog.presets || []).filter((x) => x.category !== "security").map((x) => [x.name, x.title]))),
      h("fieldset", { class: "sub" }, h("legend", { text: "Domains" }), draftChips(d.deny, "games.example", "Block during this schedule")),
    );
  };
  renderMode();

  const form = h("form", { class: "schedule-form", "aria-label": d.editing ? `Edit ${d.editing}` : "Add schedule", novalidate: true },
    h("h4", { text: d.editing ? `Edit ${d.editing}` : "Add a schedule" }),
    h("label", { class: "field" }, h("span", { text: "Name" }), name),
    h("div", { class: "field" }, h("span", { text: "Days it starts on" }), days),
    h("div", { class: "times" },
      h("label", { class: "field" }, h("span", { text: "Starts" }), start),
      h("label", { class: "field" }, h("span", { text: "Ends" }), end)),
    night,
    h("fieldset", { class: "mode" }, h("legend", { text: "Blocks" }),
      radio("all", "Block everything except…"), radio("some", "Block these"), mode),
    errors,
    h("div", { class: "actions" },
      edit(h("button", { type: "submit", class: "primary", text: d.editing ? "Save schedule" : "Add schedule" })),
      h("button", { type: "button", text: "Cancel", onClick: () => { state.draft = null; renderEditor(); } })),
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const existing = profile()?.schedules || [];
    const { schedule, errors: problems } = draftSchedule(d, existing);
    if (problems) {
      errors.replaceChildren(...problems.map((m) => h("div", { text: m })));
      return;
    }
    const next = d.editing === null
      ? [...existing, schedule]
      : existing.map((s) => (s.name === d.editing ? schedule : s));
    if (await patchProfile(p.id, { schedules: next })) {
      state.draft = null;
      renderEditor();
      toast(`${d.editing === null ? "Added" : "Saved"} ${schedule.name}`);
    }
  });
  return form;
}

// draftChips edits values, an array in a draft, in place.
export function draftChips(values, placeholder, label) {
  const chips = h("div", { class: "chips" });
  const render = () => {
    clear(chips);
    for (const v of values) {
      chips.append(h("span", { class: "chip" }, v, edit(h("button", {
        type: "button", "aria-label": `Remove ${v}`, text: "✕",
        onClick: () => { values.splice(values.indexOf(v), 1); render(); },
      }))));
    }
  };
  render();
  const input = edit(h("input", { placeholder, "aria-label": label, spellcheck: "false", autocomplete: "off" }));
  const add = () => {
    const v = input.value.trim().toLowerCase().replace(/\.$/, "");
    if (v && !values.includes(v)) values.push(v);
    input.value = "";
    render();
  };
  // Enter adds a domain here rather than submitting the schedule.
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); add(); } });
  return h("div", {}, chips, h("div", { class: "chip-form" }, input, edit(h("button", { type: "button", text: "Add", onClick: add }))));
}

export async function deleteSchedule(p, sc) {
  if (!(await confirmDialog(`Delete ${sc.name}?`, `${formatDays(sc.days)}, ${formatPeriod(sc)}. It stops blocking at once.`))) return;
  const next = (profile()?.schedules || []).filter((s) => s.name !== sc.name);
  if (await patchProfile(p.id, { schedules: next.length ? next : null })) toast(`Deleted ${sc.name}`);
}

// browserTimeZone returns the time zone this browser is in, if it says.
export function browserTimeZone() {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch { return ""; }
}

// timeZoneField picks the IANA time zone a profile's schedules follow.
// Blank is the server's local time.
export function timeZoneField(p) {
  const cur = p.time_zone || "";
  const save = (tz) => patchProfile(p.id, { time_zone: tz || null });
  let zones = [];
  try { zones = Intl.supportedValuesOf("timeZone"); } catch { /* an older browser: type it instead */ }

  let control;
  if (zones.length) {
    if (cur && !zones.includes(cur)) zones = [cur, ...zones];
    control = edit(h("select", { id: "sc-tz" },
      h("option", { value: "", text: "Server's local time" }),
      zones.map((z) => h("option", { value: z, text: z.replaceAll("_", " ") }))));
    control.value = cur;
    control.addEventListener("change", () => save(control.value));
  } else {
    const input = edit(h("input", { id: "sc-tz", value: cur, placeholder: "America/New_York", spellcheck: "false", autocomplete: "off" }));
    control = h("form", { class: "chip-form" }, input, edit(h("button", { type: "submit", text: "Save" })));
    control.addEventListener("submit", (e) => { e.preventDefault(); save(input.value.trim()); });
  }

  const browser = browserTimeZone();
  return h("div", { class: "tz" },
    h("label", { for: "sc-tz", text: "Time zone" }),
    h("div", { class: "tz-control" }, control,
      browser && browser !== cur ? edit(h("button", { type: "button", class: "small", text: `Use this browser's time zone (${browser})`, onClick: () => save(browser) })) : null),
  );
}
