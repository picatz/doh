// The device picker's logic: platforms from the setup endpoint, grouped,
// found by what people call their devices, with how well each is
// protected said in words. Pure, so it's tested on its own; connect.js
// draws it.

// LEVELS say what each protection level means, with a symbol, so it's
// never told by color alone.
export const LEVELS = {
  encrypted: { label: "Encrypted", icon: "security", tone: "ok" },
  plain: { label: "Plain DNS", icon: "warn", tone: "warn" },
  unavailable: { label: "Not available here", icon: "block", tone: "bad" },
};

// level returns a platform's protection level, as LEVELS describes it.
export const level = (p) => LEVELS[p.protection?.level] || null;

// ALIASES are other names people search for each platform by.
const ALIASES = {
  apple: "iphone ipad ios",
  mac: "macos macbook imac apple",
  "apple-tv": "tvos",
  "vision-pro": "visionos apple",
  android: "pixel samsung galaxy phone tablet",
  "android-tv": "google tv shield chromecast",
  windows: "pc laptop microsoft",
  linux: "ubuntu fedora debian systemd",
  chromeos: "chromebook",
  "smart-tv": "samsung lg roku fire tv",
  consoles: "xbox playstation ps5 ps4 switch nintendo",
  "smart-home": "alexa echo google home nest hue speaker camera",
  browser: "chrome firefox edge safari brave",
  router: "wifi wi-fi dhcp",
  pfsense: "opnsense firewall",
  unifi: "ubiquiti",
};

const words = (s) => String(s || "").toLowerCase().normalize("NFKD").replace(/[̀-ͯ]/g, "");

// groupPlatforms returns setup's groups, in order, each with its
// platforms that match query, leaving out groups with none. Every word
// of query must match a platform's name, group, ID, or aliases.
export function groupPlatforms(setup, query = "") {
  const terms = words(query).split(/\s+/).filter(Boolean);
  const groups = setup.groups?.length ? setup.groups : [{ id: "", name: "" }];
  const out = [];
  for (const g of groups) {
    const platforms = (setup.platforms || []).filter((p) => (p.group || "") === g.id || !setup.groups?.length).filter((p) => {
      if (p.id === "none") return false;
      const hay = words([p.name, p.id, g.name, ALIASES[p.id]].join(" "));
      return terms.every((t) => hay.includes(t));
    });
    if (platforms.length) out.push({ group: g, platforms });
  }
  return out;
}

// guessPlatform picks the platform of a browser by its user agent, which
// is often the device being set up, among ids.
export function guessPlatform(ua, ids, touch = 0) {
  const guess = /iPhone|iPad/.test(ua) || (/Macintosh/.test(ua) && touch > 1) ? "apple"
    : /Macintosh/.test(ua) ? "mac"
      : /CrOS/.test(ua) ? "chromeos"
        : /Android/.test(ua) ? "android"
          : /Windows/.test(ua) ? "windows"
            : /Linux/.test(ua) ? "linux" : "";
  if (ids.includes(guess)) return guess;
  // Before the platforms were split, iPhone, iPad, and Mac were one.
  return guess === "mac" && ids.includes("apple") ? "apple" : "";
}

// signingState says how an Apple configuration profile will show on a
// device: Verified only when it's signed and its certificate is trusted.
export function signingState(s) {
  if (!s) return null;
  if (s.signed && s.trusted) {
    return { verified: true, label: "Verified", line: `Signed by ${s.signer || "this server"}, so devices show the profile as Verified.` };
  }
  return {
    verified: false,
    label: s.signed ? "Signed, but not trusted" : "Unverified",
    line: s.note || (s.signed ? "Devices may show the profile as Unverified." : "The profile isn't signed, so devices show it as Unverified. It installs and works the same."),
  };
}
