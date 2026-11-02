import { checkName, reasonText } from "./activity.js";
import { api, report } from "./api.js";
import { $, buddy, clear, h, icon, toast } from "./dom.js";
import { renderProfiles } from "./profiles.js";
import { go } from "./router.js";
import { routeHash } from "./routes.js";
import { profileName, replaceProfile, state } from "./state.js";

// EXPLAIN_EXAMPLES are names to try before anyone has asked.
export const EXPLAIN_EXAMPLES = ["doubleclick.net", "xn--pple-43d.com", "wikipedia.org"];

// VERDICTS say each decision in a word, with a symbol and a tone.
export const VERDICTS = {
  allow: ["Allowed", "allow", "ok"],
  block: ["Blocked", "block", "bad"],
  rewrite: ["Answered locally", "arrow", "info"],
  refuse: ["Refused", "x", "warn"],
};

// CHECK_RESULTS say what each check did.
export const CHECK_RESULTS = { pass: ["Passed", "check"], match: ["Decided", "arrow"], skip: ["Not checked", "x"] };

// explainEmpty invites a first question.
export function explainEmpty() {
  return h("div", { class: "explain-empty" },
    buddy("calm"),
    h("p", {}, h("strong", { text: "Ask about any name." }), " doh shows what it would do, why, and every check on the way."),
    h("p", { class: "examples" }, h("span", { class: "muted", text: "Try " }),
      ...EXPLAIN_EXAMPLES.flatMap((d, i) => [i ? h("span", { class: "muted", text: " · " }) : null,
        h("button", { type: "button", class: "link mono", text: d, onClick: () => explainDomain(d) })])),
  );
}

// why says in a sentence why a query was decided as it was, naming the
// profile and the check that decided it.
export function why(x) {
  const d = x.decision || {};
  const where = x.profile ? [" in ", h("strong", { text: profileName(x.profile) })] : [];
  switch (d.action) {
    case "block": {
      const source = d.source ? reasonText({ reason: d.reason, source: d.source }).replace(/^[^:]+: /, "") : "";
      return ["Blocked", ...where, " by ", h("strong", { text: checkName(d.reason) }), source ? ` (${source})` : "", "."];
    }
    case "rewrite": return ["Answered", ...where, " by a rewrite, with ", h("span", { class: "mono", text: x.answers?.length ? x.answers.join(", ") : "local records" }), "."];
    case "refuse": return ["No profile matches this client, so the server refuses it."];
    default: return d.reason === "allow"
      ? ["It's on the allowed list", ...where, ", so nothing blocks it."]
      : ["Nothing", ...where, " blocks it, so doh asks its upstream resolvers."];
  }
}

export async function runExplain(ev) {
  ev?.preventDefault();
  const out = $("explain-result");
  const name = $("x-name").value.trim();
  if (!name) { clear(out).append(explainEmpty()); return; }
  const x = await api("GET", "/explain", {
    query: { name, type: $("x-type").value.trim() || "A", profile: $("x-profile").value, client: $("x-client").value.trim() },
  });
  const d = x.decision || {};
  const [word, sym, tone] = VERDICTS[d.action] || [d.action, "arrow", "info"];

  const facts = h("dl", { class: "facts" });
  const fact = (k, v, mono = true) => { if (v) facts.append(h("div", {}, h("dt", { text: k }), h("dd", { class: mono ? "mono" : "", text: v }))); };
  fact("Profile", x.profile && profileName(x.profile), false);
  fact("Device", x.device);
  fact("Client", x.client);
  fact("Rule", d.rule);
  fact("Response", x.rcode);

  const verdict = h("section", { class: `card verdict-card ${tone}`, "aria-labelledby": "verdict-word" },
    h("div", { class: "verdict-head" },
      h("span", { class: "verdict-icon" }, icon(sym)),
      h("div", {},
        h("p", { class: "verdict-name mono", text: `${x.name} ${x.type}` }),
        h("h3", { id: "verdict-word", class: "verdict-word", text: word }),
      ),
    ),
    h("p", { class: "verdict-why" }, ...why(x)),
    // The detail adds to the sentence, except for apps and schedules,
    // which the sentence already names.
    d.detail && d.reason !== "service" && d.reason !== "schedule" ? h("p", { class: "muted verdict-detail", text: d.detail }) : null,
    facts.childElementCount ? facts : null,
  );

  // One click to change it, with Undo on the notice that confirms it.
  const p = state.profiles.find((pp) => pp.id === x.profile);
  if (p && !state.readOnly && (d.action === "block" || d.action === "allow")) {
    const blocked = d.action === "block";
    verdict.append(h("div", { class: "actions start" }, h("button", {
      type: "button", class: blocked ? "primary" : "",
      onClick: () => changeDomain(p, x.name, blocked ? "allow" : "deny").then(() => runExplain()).catch(report),
    }, icon(blocked ? "allow" : "block"), `${blocked ? "Allow" : "Block"} it in ${p.name || p.id}`),
    h("a", { class: "button", href: routeHash("logs", "", { q: x.name }) }, icon("log"), "Find it in Activity")));
  }

  const steps = h("ol", { class: "steps-list", "aria-label": "How doh decided" },
    (x.checks || []).map((c) => {
      const [label, cicon] = CHECK_RESULTS[c.result] || [c.result, "arrow"];
      return h("li", { class: `step is-${c.result}` },
        h("span", { class: "step-dot", "aria-hidden": "true" }, icon(cicon)),
        h("div", { class: "step-body" },
          h("div", { class: "step-head" }, h("strong", { text: checkName(c.check) }), h("span", { class: "step-result", text: label })),
          c.detail ? h("p", { class: "muted", text: c.detail }) : null),
      );
    }));
  const how = h("section", { class: "card", "aria-labelledby": "how-title" }, h("h3", { id: "how-title", text: "How doh decided" }), steps);
  const answers = x.answers?.length
    ? h("section", { class: "card", "aria-labelledby": "answers-title" }, h("h3", { id: "answers-title", text: "Answers" }), x.answers.map((a) => h("div", { class: "mono answer", text: a })))
    : null;
  clear(out).append(h("div", { class: "explain-grid" }, verdict, how, answers));
}


export async function explainDomain(d) {
  $("x-name").value = d;
  $("x-type").value = "A";
  go("explain");
  await runExplain();
}

export function findInActivity(d) {
  go("logs", "", { q: d });
}

// changeDomain allows or blocks d in profile p at once, offering to undo.
export async function changeDomain(p, d, list) {
  const name = p.name || p.id;
  const path = `/profiles/${encodeURIComponent(p.id)}/${list}`;
  const updated = await api("POST", path, { body: { domain: d } });
  replaceProfile(updated);
  if (state.view === "profiles") renderProfiles();
  toast(`${list === "deny" ? "Blocked" : "Allowed"} ${d} in ${name}.`, {
    action: {
      label: "Undo",
      run: async () => {
        replaceProfile(await api("DELETE", `${path}/${encodeURIComponent(d)}`));
        if (state.view === "profiles") renderProfiles();
        toast(`Undone: ${d} is back as it was in ${name}.`);
      },
    },
  });
}

