// Protection presets: a few levels of protection to choose from, instead
// of a dozen switches. A preset sets only what it manages, the built-in
// protections, safe search, and the lists presets choose between, so a
// profile's custom lists and other choices stay as they are.
//
// Safe Browsing is never in a preset: it works only where the server's
// operator has given it an API key, so it's a choice of its own.

// FEATURES are the built-in protections presets manage.
export const FEATURES = ["rebinding", "homograph", "newly_registered", "tunneling", "bypass", "typosquatting", "dga"];

// PRESETS are the levels, from least to most.
export const PRESETS = [
  {
    id: "essential", name: "Essential",
    line: "Stops attacks and known threats, and nothing else.",
    features: ["rebinding", "homograph"], lists: ["threat-intel"], safeSearch: false,
  },
  {
    id: "recommended", name: "Recommended",
    line: "Also blocks scams, brand-new domains, and ads and trackers.",
    features: ["rebinding", "homograph", "newly_registered"], lists: ["threat-intel", "scams", "hagezi-normal"], safeSearch: false,
  },
  {
    id: "strict", name: "Strict",
    line: "Also stops tunneling, bypass tricks, look-alike and machine-made domains, and risky ones. A few sites may break.",
    features: FEATURES, lists: ["threat-intel", "scams", "abused-tlds", "dynamic-dns", "bypass-services", "hagezi-pro"], safeSearch: false,
  },
  {
    id: "kids", name: "Kids",
    line: "Strict, with safe search and no adult or gambling sites.",
    features: FEATURES, lists: ["threat-intel", "scams", "abused-tlds", "dynamic-dns", "bypass-services", "hagezi-pro", "adult", "gambling"], safeSearch: true,
  },
];

// MANAGED are the lists presets choose between; other lists are left be.
const MANAGED = new Set([...PRESETS.flatMap((p) => p.lists), "hagezi-light", "threat-intel-full"]);

const sameSet = (a, b) => a.size === b.size && [...a].every((x) => b.has(x));

// matchPreset returns the ID of the preset profile p matches, or "" for
// its own mix.
export function matchPreset(p) {
  const on = new Set(FEATURES.filter((f) => p.security?.[f]));
  const lists = new Set((p.lists || []).filter((l) => MANAGED.has(l)));
  const match = PRESETS.find((pr) => sameSet(on, new Set(pr.features)) && sameSet(lists, new Set(pr.lists)) && !!p.safe_search === pr.safeSearch);
  return match?.id || "";
}

// presetPatch returns the merge patch that applies preset to p.
export function presetPatch(p, preset) {
  const kept = (p.lists || []).filter((l) => !MANAGED.has(l));
  return {
    security: Object.fromEntries(FEATURES.map((f) => [f, preset.features.includes(f)])),
    lists: [...kept, ...preset.lists],
    safe_search: preset.safeSearch,
  };
}

// undoPatch returns the merge patch that puts back what presetPatch
// changes in p.
export function undoPatch(p) {
  return {
    security: Object.fromEntries(FEATURES.map((f) => [f, !!p.security?.[f]])),
    lists: [...(p.lists || [])],
    safe_search: !!p.safe_search,
  };
}
