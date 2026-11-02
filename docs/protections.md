# Profiles and protections

`doh serve` applies a **policy** to every query: a set of **profiles**, each the rules for a group of devices. A profile chooses which protections are on, which blocklists apply, which domains are always allowed or denied, and how blocked names are answered. Every decision can be traced, logged, and undone.

- [How a query is decided](#how-a-query-is-decided)
- [Protections](#protections)
- [Blocklists](#blocklists)
- [Apps and schedules](#apps-and-schedules)
- [Profiles and devices](#profiles-and-devices)
- [Setting up devices](#setting-up-devices)
- [The policy file](#the-policy-file)
- [Local names and forward zones](#local-names-and-forward-zones)
- [Query log](#query-log)
- [Admin API and web UI](#admin-api-and-web-ui)
- [Reliability](#reliability)
- [Sharing a server](#sharing-a-server)
- [Following another server's policy](#following-another-servers-policy)
- [Troubleshooting](#troubleshooting)
- [Limits](#limits)

## How a query is decided

```mermaid
flowchart TD
    Q["Query"] --> P{"Which profile?"}
    P -- "DoH path, host name, client address, then default" --> C["Checks, in order"]
    P -- "no profile matches" --> R["REFUSED"]
    C -- "a check matches" --> B["Blocked: NXDOMAIN or 0.0.0.0<br/>with an Extended DNS Error"]
    C -- "rewrite or safe search" --> W["Answered locally"]
    C -- "allowed" --> L{"Special-use name?"}
    L -- "yes" --> W
    L -- "no" --> U["Cache, or upstream"]
    U --> A["Answer checks: CNAME targets, rebinding"]
    A -- "match" --> B
    A -- "pass" --> OK["Answer"]
```

The first check that matches decides. `doh explain` (or **Explain** in the web UI) shows every step for any name:

```console
$ doh explain xn--pple-43d.com
xn--pple-43d.com A: BLOCK by homograph (xn--pple-43d.com)
  mixed scripts (Cyrillic, Latin) in аpple
  as profile default

Checks:
  ✓ rewrite    no rewrite
  ✓ allow      not on the allow list
  ✓ deny       not on the deny list
  – bypass     bypass protection is off
  ✓ tld        TLD not blocked
  ✓ list       on none of 1 lists (1 loaded)
  ✗ homograph  mixed scripts (Cyrillic, Latin) in аpple

Answer: NXDOMAIN
```

| Order | Check | What it does |
| --- | --- | --- |
| 1 | `upstream` | The server's own upstream hosts are never filtered, so it can't cut itself off. |
| 2 | `rewrite` | The profile's local answers, such as `nas.home.arpa` → `192.168.1.5`. |
| 3 | `allow` | Allowed domains skip **every** other check, including answer checks. |
| 4 | `deny` | Denied domains are always blocked. |
| 5 | `service` | Blocked apps and sites, such as TikTok. |
| 6 | `schedule` | Schedules in effect now. |
| 7 | `bypass` | Firefox's DoH canary; with bypass protection, Private Relay and public encrypted DNS. |
| 8 | `tld` | Blocked top-level domains. |
| 9 | `list` | Blocklists, unless any of the profile's lists has an exception for the name. |
| 10 | `homograph` | Look-alike internationalized names. |
| 11 | `tunneling` | Data smuggled through DNS. |
| 12 | `newly-registered` | Domains registered recently. |
| 13 | `safe-search` | Safe search hosts for search engines and YouTube. |
| 14 | `cname` | Answers whose CNAME targets are denied, under a blocked TLD, or on a blocklist. |
| 15 | `rebinding` | Answers that point public names at local addresses. |

Blocked names get `NXDOMAIN` (or, with `block_response: "null"`, `0.0.0.0` and `::`), a synthetic SOA so they're cached for only a minute, and an [Extended DNS Error](https://www.rfc-editor.org/rfc/rfc8914.html#section-4.16) naming the reason, such as `blocked: rebinding` or `blocked by threat-intel`.

## Protections

New policies turn on the protections that don't cause false positives on typical networks, and the threat intelligence list.

| Protection | Field | Default | How it works |
| --- | --- | --- | --- |
| DNS rebinding | `security.rebinding` | on | Blocks answers that point a public name at a loopback, [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918.html), unique local, link-local (including cloud metadata at `169.254.169.254`), or unspecified address. IPv4 addresses inside IPv4-mapped and [NAT64](https://www.rfc-editor.org/rfc/rfc6052.html) addresses, and the address hints of [HTTPS records](https://www.rfc-editor.org/rfc/rfc9460.html#section-7.3), are checked too. Local names and forward zones are exempt. Shared address space (`100.64.0.0/10`, used by Tailscale and carrier-grade NAT) is allowed. |
| Look-alike domains | `security.homograph` | on | Decodes [Punycode](https://www.rfc-editor.org/rfc/rfc3492.html) labels and blocks names that mix scripts beyond what [UTS #39's Highly Restrictive level](https://www.unicode.org/reports/tr39/#Restriction_Level_Detection) allows (`аpple.com` with a Cyrillic `а`), are spelled entirely in Cyrillic or Greek letters that look Latin (`аррӏе.com`) outside TLDs where those scripts are expected, contain invisible characters, use deceptive Latin letters such as `ɡ`, or aren't valid IDNA. Plain ASCII names are never affected. |
| Newly registered domains | `security.newly_registered`, `security.newly_registered_days` | off | Looks up each registered domain's creation date with [RDAP](https://www.rfc-editor.org/rfc/rfc9083.html#section-4.5), finding the registry through [IANA's bootstrap](https://www.rfc-editor.org/rfc/rfc9224.html), and blocks domains younger than 30 days (or your threshold). Lookups are cached (on disk, in the data directory) and shared by concurrent queries; if a lookup fails or the TLD has no RDAP service, the name is allowed. |
| DNS tunneling | `security.tunneling` | off | Blocks `NULL` queries, labels of 52 or more characters, labels of 30 or more characters with the randomness of encoded data (≥ 4.2 bits per character, above any hex hash), and, per client, a domain after 100 unique names under it in a minute, for 10 minutes. |
| Bypass methods | `security.bypass` | off | Answers [iCloud Private Relay's canaries](https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/) negatively and blocks well-known public encrypted DNS services (except your upstreams). For broader coverage, add the `bypass-services` list. |
| Safe search | `safe_search` | off | Answers Google, Bing, DuckDuckGo, and Pixabay with their safe search hosts, and YouTube with restricted mode, as each provider documents. Applies to every record type, so HTTPS records can't route around it. |

[Firefox's canary domain](https://support.mozilla.org/kb/canary-domain-use-application-dnsnet) gets `NXDOMAIN` in every profile that blocks anything, so Firefox keeps using this resolver instead of enabling its own DoH.

Every check also runs on **CNAME targets** in answers, against the profile's deny list, blocked TLDs, and blocklists. This uncovers trackers cloaked behind a first-party name, such as `metrics.shop.example CNAME collect.tracker.example`.

## Blocklists

Profiles list blocklists by preset name, URL, or file path, optionally named as `name=location`. Each list is downloaded once, however many profiles use it, cached on disk, revalidated with conditional requests, and refreshed daily (`--blocklist-refresh`). Lists a profile adds load in the background; until they do, they block nothing, and `doh status` shows them loading.

| Category | Presets |
| --- | --- |
| Security | `threat-intel` (default), `threat-intel-full`, `scams`, `abused-tlds`, `dynamic-dns`, `bypass-services` |
| Privacy | `hagezi-light`, `hagezi-normal` (`default`), `hagezi-pro`, `oisd-small`, `oisd-big`, `stevenblack`, `easylist`, `easyprivacy` |
| Parental | `gambling`, `adult`, `social` |

`doh blocklist presets` describes each one. `--blocklist`, `--block-domain`, `--allow-domain`, and `--block-response` apply to **every** profile, as a baseline; a profile's allow list overrides baseline blocks.

## Apps and schedules

Profiles can block apps and sites by name, always or on a schedule.

**Services** block an app's domains with one setting. The catalog covers 93 apps across social, messaging, video and streaming, music, gaming, AI chat, shopping, dating, and gambling and betting; `doh services` lists them, `doh services chat` searches, and the web UI's Apps section has the same search. Each lists only domains the service owns, never shared ones such as `googleapis.com`, and each domain belongs to one service, so blocking one doesn't break another: Messenger is its own service, separate from Facebook. Where a service lives on part of a large company's domain, only that part is listed, so `gemini` blocks `gemini.google.com` but not the rest of Google. CNAME targets are checked too, so an app can't slip through behind another name. Apps change their domains, though, so a blocked service is a strong default, not a guarantee; add domains to deny alongside it if something gets through. Whole categories of sites, beyond the apps listed, are better blocked with the `social`, `gambling`, and `adult` lists.

**Schedules** block more during a recurring period, in the profile's `time_zone` (an IANA name such as `America/New_York`; the server's own by default):

```json
{
  "id": "kids",
  "time_zone": "America/New_York",
  "services": ["tiktok"],
  "schedules": [
    { "name": "Homework", "days": ["mon", "tue", "wed", "thu", "fri"], "start": "15:00", "end": "18:00",
      "services": ["youtube", "roblox"], "lists": ["social"] },
    { "name": "Bedtime", "days": ["sun", "mon", "tue", "wed", "thu"], "start": "21:00", "end": "07:00",
      "block_all": true, "allow": ["school.example"] }
  ]
}
```

A period that ends before it starts runs past midnight and belongs to the day it starts on: Thursday's bedtime lasts into Friday morning, and Friday night has none. One that ends when it starts, such as `00:00` to `00:00`, lasts all day on its days. During a period, the schedule's services, lists, and denied domains are blocked; with `block_all`, everything is, except the profile's allowed domains, the schedule's `allow`, and names local to the network, such as the router and printer. Blocked queries are logged with reason `schedule` and the schedule's name, and the block says until when, as in "Homework: YouTube is blocked until 18:00", or "today" for an all-day one. That sentence is the log entry's `detail`, shown as "Why" in the web UI.

## Profiles and devices

A query is matched to a profile by, in order:

1. **The DoH path.** `https://doh.example.com/dns-query/kids` uses profile `kids`; `/dns-query/kids/tablet` also names the device `tablet` in the log. Unknown profiles get `404`. Profile IDs are identifiers, not secrets: anyone who knows one can use that profile.
2. **The host name**, with `--hostname dns.example.com` (or an ACME domain): over DoT, the TLS server name, and over DoH, the host. `kids.dns.example.com` selects profile `kids`, and `tablet--kids.dns.example.com` also names the device. Names under the hostname that name no profile are refused, rather than falling back to another profile. `doh setup` prints the right settings for each platform.
3. **The client's address**, against every profile's `clients` (addresses or prefixes) and `devices`. The most specific prefix wins, so a device listed by address overrides the network it's on. Behind a reverse proxy, set `--trusted-proxy` so `X-Forwarded-For` names the client; it's ignored from anyone else.
4. **The `default` profile.** Remove it to make the server **closed**: queries from unmatched clients get `REFUSED` with an Extended DNS Error, which keeps a server on the internet from being an open resolver.

```console
$ doh profile create streaming --name "Streaming sticks"
$ doh profile set streaming clients=192.168.1.40/29 security.newly_registered=true security.bypass=true
$ doh allow some-new-streaming-cdn.example --profile streaming
$ doh profile set kids safe_search=true lists=threat-intel,adult,gambling
```

`doh profile set` turns `key=value` pairs into a [JSON merge patch](https://www.rfc-editor.org/rfc/rfc7396.html). An empty value (`key=`) resets a field.

## Setting up devices

`doh setup <profile>` (with `--device` to name the device, `--list` for a table, and `--platform` for one platform or group), the API's `GET /api/v1/profiles/{id}/setup`, the web UI's Connect tab, and [setup links](#setup-links) all give the same instructions, worked out from how the server runs: encrypted settings need `--hostname` and DoH (and `--dot-listen` for DNS-over-TLS); plain DNS needs `--dns-listen` on your network. Each platform says how well it's protected, how to check it's working, and how doh tells which device is asking. Platforms a server can't serve as it runs are listed as not available, with what it would take.

| Device | Method | Protection | How doh knows the device |
| --- | --- | --- | --- |
| iPhone, iPad (iOS 14+), Mac (macOS 11+), Apple Vision Pro | Configuration profile (`apple.mobileconfig`): DoH, a DoT version, and a locked version for supervised devices | Encrypted, every network | Profile and device in the DoH URL or DoT host name |
| Apple TV | The same profile, installed with Apple Configurator or MDM (not from a download); otherwise DNS by address | Encrypted, if installed; untested here | As above |
| Android 9+ | Private DNS host name, such as `tablet--kids.dns.example.com` | Encrypted (DoT), every network | DoT host name |
| Android TV, Google TV | Private DNS where the TV shows it, or `adb shell settings put global private_dns_mode hostname` and `private_dns_specifier`; otherwise DNS by address | Encrypted (DoT) where possible | DoT host name, or address |
| Windows 11 | `doh-setup.ps1` (`-WhatIf`, `-Revert`), or Settings by hand | Encrypted (DoH), no fallback | DoH URL |
| Windows 10 | A browser's secure DNS, plus plain DNS | Browser only | DoH URL, or address |
| Linux | systemd-resolved drop-in `doh.conf` for `/etc/systemd/resolved.conf.d/` | Encrypted (DoT), strict | DoT host name |
| Chromebook | Settings, Use secure DNS, custom provider | Encrypted (DoH) | DoH URL |
| Chrome, Edge, Brave, Firefox | Custom secure DNS provider | Encrypted, that browser only | DoH URL |
| Smart TVs and sticks (Samsung, LG, Roku, Fire TV, Chromecast), consoles (PlayStation, Xbox, Switch), smart speakers and other devices | DNS by address, best set on the router; some on the device | Plain DNS | Client address |
| Any router, OpenWrt (`doh-openwrt.sh`), UniFi | DHCP hands out doh's address | Plain DNS | Each device's address |
| pfSense, OPNsense | Unbound forwarding to doh over DoT, or DHCP as above | Encrypted from the firewall; plain on your network | The firewall, by DoT host name; or each device's address |

Over plain DNS, doh knows a device only by its address: add it to a profile's `devices` (or its network to `clients`), and give it a DHCP reservation in the router so the address stays the same. Plain DNS isn't encrypted on your network. Some devices, including some Chromecasts and Rokus, use DNS servers built into them and ignore the network's; only a router or firewall that redirects port 53 to doh catches those, and the `bypass` protection blocks the public encrypted DNS services apps could switch to. Leave no public DNS server as a secondary anywhere, or devices use it to skip doh.

The files are generated from the profile, device, and server: `GET /api/v1/profiles/{id}/{file}` for `apple.mobileconfig`, `doh-setup.ps1`, `doh.conf`, and `doh-openwrt.sh` (any reader of that profile, tenants only for their own), and the same names under a setup link, for its device only, while it lasts. Scripts fetch nothing, change only DNS settings, and explain each line. The Windows script and Linux drop-in name the server's addresses: what `--hostname` resolves to, as the server sees it, or its own local addresses; without one, the script looks the name up when it runs, and the drop-in isn't offered. `doh setup <profile> --platform windows --download doh-setup.ps1` saves one.

Encrypted profiles from Apple devices can't make an exception for captive Wi-Fi sign-in pages; if one won't load, remove the profile until you're signed in. Device menus change between versions and makers, so steps name settings rather than promise exact paths where they vary.

## The policy file

Profiles live in `policy.json` in the data directory (`--data-dir`: `$STATE_DIRECTORY` under systemd, otherwise `doh` in your configuration directory). It's created with the defaults on first run, readable only by its owner, and reloaded within seconds of being edited by hand. An invalid edit is logged and ignored, keeping the current policy. A server won't start with an invalid policy file.

```json
{
  "version": 1,
  "profiles": [
    {
      "id": "default",
      "name": "Default",
      "security": { "rebinding": true, "homograph": true, "newly_registered": false, "tunneling": false, "bypass": false },
      "lists": ["threat-intel"],
      "rewrites": [{ "name": "nas.home.arpa", "addrs": ["192.168.1.5"] }],
      "safe_search": false
    },
    {
      "id": "streaming",
      "name": "Streaming sticks",
      "devices": [{ "name": "living-room-tv", "addrs": ["192.168.1.50"] }],
      "security": { "rebinding": true, "homograph": true, "newly_registered": true, "newly_registered_days": 14, "tunneling": false, "bypass": true },
      "lists": ["threat-intel", "hagezi-normal"],
      "allow": ["gef.sh"],
      "safe_search": false
    }
  ]
}
```

Unknown fields, duplicate keys, and every invalid value are rejected, with each problem listed, so a policy that loads is a policy that applies. `--policy off` turns profiles off, leaving only the baseline blocklist flags.

## Local names and forward zones

Some names mean nothing on the public internet, so the server answers them itself rather than leaking them upstream:

| Names | Answer | Why |
| --- | --- | --- |
| `localhost` and its subdomains | `127.0.0.1` and `::1` | [RFC 6761, Section 6.3](https://www.rfc-editor.org/rfc/rfc6761.html#section-6.3) |
| `invalid`, `local` | `NXDOMAIN` | [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761.html#section-6.4), [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762.html#section-3) |
| `home.arpa` | `NXDOMAIN` | [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375.html#section-4) |
| `resolver.arpa` | no records | Forwarding it would let clients discover the upstream's encrypted resolver and bypass this one ([RFC 9462, Section 6.5](https://www.rfc-editor.org/rfc/rfc9462.html#section-6.5)). |
| Reverse lookups of private, loopback, link-local, documentation, and shared addresses | `NXDOMAIN` | [RFC 6303](https://www.rfc-editor.org/rfc/rfc6303.html#section-4), [RFC 7793](https://www.rfc-editor.org/rfc/rfc7793.html) |

To resolve your network's own names, forward their domains to the resolver that knows them, usually the router. Forwarded domains count as local, so their answers may point to private addresses:

```console
$ doh serve --dns-listen :53 --forward lan=192.168.1.1 --forward 168.192.in-addr.arpa=192.168.1.1
```

Or answer a name yourself with a profile rewrite, as `nas.home.arpa` in the example above.

### Device names

The query log names devices without anyone typing names in: it learns what each device on the local network calls itself, and shows `living-room-tv` rather than `192.168.1.50`. Names come from, in order:

1. DHCP lease files, with `--dhcp-leases`, when doh runs beside the DHCP server: dnsmasq's (as on OpenWrt and Pi-hole), or Kea's CSV files.
2. Reverse lookups through forward zones that cover the device's address, such as `--forward 168.192.in-addr.arpa=192.168.1.1`: most home routers answer them with their DHCP clients' hostnames.
3. Reverse lookups to `--device-names-from`, or with none set, to the default gateway (on Linux).

Names are looked up in the background, only for private, unique local, and link-local addresses, and cached for an hour, so answering never waits on them: a new device is named from its next query on. Stats count each device once, however its name was known.

Devices choose their own hostnames, so a name like `kids-tablet` proves nothing. Learned names are shown as a device's `hostname`, apart from the device names you configure, and never select a profile or affect any other decision. `--no-device-names` turns them off.

## Query log

Every query is logged with its profile, device, client, name, type, outcome, reason, matching rule and list, answers, upstream, and duration. The newest 50,000 entries are kept in memory to search, and every entry is written to a daily file in `querylog/` in the data directory, which is reloaded on restart and deleted after `--query-log-retention` (seven days by default). Turn logging off for a profile with `"logging": {"disabled": true}`, or for the whole server with `--no-query-log`; queries are still counted in metrics.

```console
$ doh log --blocked -n 5
TIME      CLIENT          STATUS   TYPE  NAME                      REASON
18:53:08  living-room-tv  blocked  A     ads.example.net           list (hagezi-normal)
$ doh log -f --profile kids         # follow live
$ doh log --json -q google | jq .   # JSON lines
```

## Alerts

Alerts tell someone when something on the network needs them, without opening the web UI: as a notification from the web UI installed on a phone or computer ([Web Push](#web-push)), by [email](#email), through [ntfy](https://ntfy.sh), or to anything that takes a webhook, such as Home Assistant.

Set them up in the web UI's **Security** view (Alerts: what to hear about, quiet hours, where they go, and a test), or from the command line:

```sh
doh alerts add-ntfy https://ntfy.sh/smith-family-7f3a --name "Family phones"
doh alerts add-webhook https://hooks.example.com/doh --name "Home Assistant"   # prints its signing secret, once
doh alerts add-email alex@example.com --name "Alex"                            # sends a code to confirm it
doh alerts confirm 7KQ2M-X9D4H                                                 # or the address's owner opens the emailed link
doh alerts set kinds=threat,new-device quiet=22:00-07:00 tz=America/New_York
doh alerts test                                                                # one test alert to each destination
doh alerts show                                                                # settings, destinations, recent deliveries
doh alerts remove 3f2a9c0d1e4b5a67
```

| Kind | Sent when | For example |
| --- | --- | --- |
| `threat` | A query is blocked by a security protection (look-alike name, tunneling, rebinding, newly registered domain, bypass service) or by a list in the security category, such as `threat-intel` or `scams` | **Threat blocked on kids-ipad.** doh blocked evil-c2.example, a known malware, phishing, or command-and-control domain (Threat intelligence list), for Kids' tablets. Nothing reached it. |
| `new-device` | A device, by its configured name or its address, uses doh for the first time | **New device: living-room-tv.** living-room-tv started using doh, with the Home profile. Its address is 192.168.1.50. |
| `failing` | At least 20 lookups, and at least 10% of them, fail within about five minutes | **Lookups are failing.** In the last 5 minutes, 34 of 120 lookups (28%) failed, so some sites and apps may not load. |
| `list-failed` | A blocklist fails to load (the operator's only) | **Blocklist didn't load: Threat intelligence.** doh couldn't load the Threat intelligence list (threat-intel): … |

Every kind is on once there's a destination. Blocks by privacy and parental lists, apps, and schedules aren't threats, and neither are the canaries Firefox and iCloud Private Relay look up to ask whether they may bypass the network's resolver: blocking them is the answer. With `--admin-origin` set, each alert links to what it's about in the web UI.

- **Calm by default.** The same alert (the same threat on the same device, the same new device, failing lookups, the same list) is sent at most once an hour. After three alerts of a kind about one device (or, for new devices, about the network) in an hour, the rest are held and summarized when the hour is up: "12 more threats blocked on kids-ipad in the last hour", with a few of their names.
- **New devices are learned first.** For the first hour after doh starts seeing devices, they're recorded without alerts, so turning alerts on doesn't report every device already there. The devices seen, up to 2,048 per tenant (forgetting the least recently seen beyond that), are kept in `alerts.json`, so restarts don't report them again.
- **Quiet hours** hold every alert but threats, in the time zone given (or the first profile's, or UTC), and send what was held when they end: one alert as itself, several as "3 new device alerts during quiet hours", listing them. A period like `22:00-07:00` runs past midnight.
- **Tenants get only their own.** A tenant's alerts are only ever about its own profiles' queries. The operator's cover every query outside tenants, failing lookups across the whole server (how it's run is the operator's concern; tenants' failing alerts count only their own queries and leave out the server's errors), and lists that fail to load.
- **Managing alerts takes an admin person, or the operator's token.** Destinations receive query names, and a destination's URL can be enough to read them, so readers can't see alert settings, and service accounts, even admin ones, are refused. The operator manages any tenant's with `--tenant`. Changes are logged as `admin: alert ...` lines.

### Webhooks

Each alert is a JSON `POST`:

```json
{
  "id": "msg_9c41f0b2d7e35a68",
  "type": "alert.threat",
  "scope": "smiths",
  "kind": "threat",
  "title": "Threat blocked on kids-ipad",
  "body": "doh blocked evil-c2.example, a known malware, phishing, or command-and-control domain (Threat intelligence list), for Kids' tablets. Nothing reached it. See it: https://admin.dns.example.com/#/logs?device=kids-ipad&profile=kids&q=evil-c2.example&status=blocked",
  "time": "2026-11-02T19:04:05Z",
  "details": {
    "profile": "kids",
    "device": "kids-ipad",
    "client": "192.168.1.20",
    "name": "evil-c2.example",
    "reason": "list",
    "list": "threat-intel",
    "detail": "blocked by threat-intel",
    "link": "https://admin.dns.example.com/#/logs?device=kids-ipad&profile=kids&q=evil-c2.example&status=blocked"
  }
}
```

| Field | Meaning |
| --- | --- |
| `id` | The alert's ID, also its `webhook-id`, the same across retries, so receivers can ignore duplicates |
| `type` | `alert.` and the kind: `alert.threat`, `alert.new-device`, `alert.failing`, `alert.list-failed`, or `alert.test` |
| `scope` | The tenant, or `""` for the server's operator |
| `kind`, `title`, `body`, `time` | What happened, for people, and when (RFC 3339, UTC) |
| `details` | The facts, for programs; fields that don't apply are left out: `profile`, `device`, `hostname`, `client`, `name`, `reason`, `list`, `detail` (as in the query log), `queries` and `errors` (failing lookups), `error` (the operator's failing lookups and lists), `count` and `names` (summaries), and `link` |

Deliveries are signed as the [Standard Webhooks](https://www.standardwebhooks.com/) specification describes, so its libraries verify them. Adding a webhook shows its secret, `whsec_` and a base64 key, once; doh keeps it to sign with, and never shows it again. Each request has these headers:

- `webhook-id`: the alert's ID.
- `webhook-timestamp`: when it was sent, in seconds since the Unix epoch.
- `webhook-signature`: `v1,` and the base64 HMAC-SHA256, keyed with the secret's decoded key, of `<webhook-id>.<webhook-timestamp>.<body>`.

To verify one by hand, recompute the signature over the raw body, compare in constant time, and reject timestamps more than five minutes off, so a captured delivery can't be replayed:

```python
import base64, hashlib, hmac, time

def verify(secret: str, headers, body: bytes) -> None:
    key = base64.b64decode(secret.removeprefix("whsec_"))
    msg_id, timestamp = headers["webhook-id"], headers["webhook-timestamp"]
    if abs(time.time() - int(timestamp)) > 300:
        raise ValueError("stale webhook")
    mac = hmac.new(key, f"{msg_id}.{timestamp}.".encode() + body, hashlib.sha256).digest()
    expected = "v1," + base64.b64encode(mac).decode()
    if not any(hmac.compare_digest(expected, sig) for sig in headers["webhook-signature"].split()):
        raise ValueError("invalid signature")
```

### Web Push

The web UI can show alerts as notifications, on phones and computers, with no app or account elsewhere: doh sends them itself, through the push service each browser already uses (Google's for Chrome and Edge on Android, Mozilla's, Apple's, Microsoft's). [Install the app](#installing-the-app); the UI's `push.js` asks the browser to allow notifications, subscribes it, and adds it as a `push` destination. (The Security view's button for this is still being added to the redesigned UI; until then, nothing in the UI calls it.) `doh alerts show` lists browsers like any destination, and `doh alerts remove` removes one.

- **Encrypted end to end.** Each notification is encrypted for the one browser ([RFC 8291](https://www.rfc-editor.org/rfc/rfc8291.html), aes128gcm), so the push service carries it without reading it, and signed with the server's VAPID key ([RFC 8292](https://www.rfc-editor.org/rfc/rfc8292.html)), which doh makes the first time it's needed and keeps in `push-vapid.pem` in the data directory, readable only by the server's user. `GET /api/v1/alerts/push-key` returns its public half. Replacing the file ends every subscription; each browser must subscribe again.
- **Only to push services.** A subscription's endpoint must be https on `fcm.googleapis.com`, `updates.push.services.mozilla.com`, `web.push.apple.com` or another `*.push.apple.com`, or `*.notify.windows.com`, on the default port, and tenants' still go through the same address checks as every other destination. The endpoint and keys are never shown: the API shows the push service, and `subscription`, the SHA-256 of the endpoint, which the browser can compute to recognize itself.
- **What's sent.** The title, body, a tag (so a newer alert about the same device replaces the last), and a link into the UI, which the service worker opens only on the UI's own origin. Threats are sent with high urgency; push services keep alerts for an offline browser for a day (failing lookups and tests, an hour). A push service's `404` or `410` means the browser unsubscribed, so it's marked `gone` and sent nothing more until it subscribes again; a `429` is retried after its `Retry-After`, up to two minutes.

### Email

With a mail server set up by the server's operator, alerts can go to email addresses, as a short text and HTML email (no images, nothing loaded from elsewhere) with a link into the UI.

```sh
doh serve ... --smtp-url smtp://alerts@mail.example.com:587 --smtp-password-file /etc/doh/smtp.password --smtp-from "doh <alerts@example.com>"
```

- **The connection is encrypted.** `smtp://` requires STARTTLS, and `smtps://` (port 465) uses TLS from the start; certificates are verified, and only a mail server on loopback may be spoken to in the clear. The password is read from `--smtp-password-file`, or once from `DOH_SMTP_PASSWORD`, which doh then removes from its environment; there's no flag for it, a password in the URL is refused, and it's never logged or shown.
- **Addresses confirm first.** Adding one sends it a code, `XXXXX-XXXXX`, that works once, for 24 hours; the address gets nothing else until the code is given back with `doh alerts confirm` (or `POST /api/v1/alerts/confirm`), or its owner opens the link in the email (with `--admin-origin`) and presses Confirm. The code is never shown to whoever added the address, and only its hash is kept. The confirmation email names the server, not the tenant, so tenants can't put their own words in strangers' inboxes. Adding a pending address again sends a new code.
- **Limits.** Each tenant (and the operator) may have 3 addresses, confirmed or not; send 5 confirmation emails an hour; and try 10 wrong codes an hour. Each address is sent at most 3 confirmation emails a day, from every tenant together, and 20 alerts an hour. The confirmation page allows 20 wrong codes per client, then one every three minutes.
- **Unsubscribing.** With `--admin-origin`, each alert email has a one-click unsubscribe link ([RFC 8058](https://www.rfc-editor.org/rfc/rfc8058.html)) for whoever reads it, which needn't be someone who can sign in. Opening the confirm or unsubscribe link changes nothing by itself (mail scanners open links); the page asks for a button press.

### Installing the app

The web UI is an installable web app: in Chrome or Edge, use Install in the address bar or menu; on Android, Add to Home screen; on iPhone and iPad, Share, then Add to Home Screen (iOS delivers web notifications only to apps added this way). It opens in its own window, with doh's icon. Its service worker, at `/sw.js`, only shows notifications and opens them; it caches nothing, so query logs never sit on the device, and every page load is fresh. Notifications need the UI on https (or `localhost`), so set `--admin-origin` to the https origin it's opened at.

### ntfy

An ntfy destination gets the alert's body as plain text, with its title, a tag (shown as an emoji), a priority (high for threats and failing lookups), and its web UI link in ntfy's `Title`, `Tags`, `Priority`, and `Click` headers ([publishing](https://docs.ntfy.sh/publish/)). Subscribe to the topic in the ntfy app on each phone. Anyone who knows a topic's name on a public ntfy server can read it, so choose one that's hard to guess, or run a server with access control and give its credentials in the URL (`https://user:password@ntfy.example.com/topic`); passwords in URLs are never shown.

### Delivery

- **Destinations use HTTPS.** The operator may use plain HTTP only to a loopback address, for testing. A tenant's destinations must be on the internet: doh refuses, when they're added and again for every address it connects to, loopback, private, link-local (including cloud metadata services), shared, and other special-purpose addresses, so a tenant can't make the server reach services on its own network. Redirects are never followed, and nothing about an alert is ever added to a URL.
- **Each alert is tried up to four times**, waiting 2, 10, and 30 seconds between tries, each with a 10-second timeout. A `2xx` response delivers it; `408`, `429`, `5xx`, and network errors are retried; other responses, and redirects, fail at once.
- **Every delivery is recorded**: `doh alerts show` lists the last 20 since the server started, and each destination's last success and last error. Failures are also logged, as `alerts: delivery failed`.

## Admin API and web UI

With `--admin-listen`, the admin listener serves a web UI at `/` and a JSON API at `/api/v1`, alongside metrics and profiling. The UI toggles every protection and list, edits allow and deny lists, devices, and rewrites, connects devices (and sends a device a [setup link](#setup-links) to open itself), searches and follows the query log (its **Activity** view), allows or blocks a name from any log entry in one click, and explains any decision.

Its Overview shows today as a ring: a 24-hour clock with midnight at the top, each hour's glaze as thick as its traffic, and a sprinkle for blocked queries. Point at an hour for its numbers, or open it for its queries; every number on the page links to the queries behind it, and what needs attention, such as failed queries or a list that didn't load, comes first, with what to do about it.

It works the same by mouse, touch, and keyboard, on phones, tablets, and desktops, in light and dark themes. Every view has a URL. Press <kbd>⌘K</kbd> (<kbd>Ctrl K</kbd>) to jump anywhere, or type a domain to explain, find, block, or allow it; changes made this way can be undone from the notice that confirms them. Press <kbd>?</kbd> for every shortcut. [docs/design.md](design.md) describes the principles behind it.

### Setup links

Setting up a phone from a laptop is awkward, so the Connect tab can make a setup link instead: `https://<hostname>/setup/<code>`, served by the public DoH listener, to open on the device itself. It shows one button to install the Apple configuration profile, then every platform, grouped, with its protection level, steps, and setup files, served under the link for its device. A link works for 30 minutes and only says how to reach one profile, which its ID already does; it reveals nothing else, the page runs no scripts, and it isn't cached or indexed. The Connect tab shows it as a QR code to scan with the device's camera, in doh's colors with its donut in the middle (the donut covers no more than half of what each part of the code can correct, so it still reads in poor light), and `doh setup <profile> --link` prints one in the terminal. Making one takes an admin, and needs `--hostname` and DoH.

### Signing in

Browsers never hold an API token. Instead:

```console
$ doh serve --dns-listen :53 --admin-listen localhost:9090
$ doh ui
http://localhost:9090/#signin=…
```

`doh ui` creates a **sign-in link** through the API: single-use, valid for five minutes, with its code in the URL fragment, which browsers never send to servers, so it stays out of logs. Opening it gives the browser a session cookie that scripts can't read (`HttpOnly`), that other sites can't send (`SameSite=Strict`), and that's `Secure` and host-only (`__Host-`) over HTTPS. Sessions end after two hours unused, or twelve hours at most.

Signed in, add a **passkey** ([WebAuthn](https://www.w3.org/TR/webauthn-3/)): Face ID, Touch ID, Windows Hello, a phone, or a security key. From then on:

- A passkey signs in on its own. It needs your device and its biometric or PIN, and can't be phished: it only works at the UI's own origin.
- A sign-in link becomes a first factor only: it starts a sign-in that a passkey must finish. A leaked link, or a stolen token that makes them, isn't enough.

Passkeys are verified by a native WebAuthn relying party ([`internal/webauthn`](../internal/webauthn)), with single-use challenges bound to the browser's session, user verification required, and every response bounded. People and their passkeys are kept in `people.json` in the data directory. Sign-in attempts are rate limited per client, and sessions that haven't finished signing in can't crowd out those that have.

If everyone loses their passkeys, an operator with the admin token removes them (`doh people remove`), and sign-in links work on their own again.

**In the browser**, every response from the admin listener and the setup pages carries the same defenses ([`internal/httpsec`](../internal/httpsec)), each backing up something the code already avoids:

- A Content-Security-Policy with no inline code, nothing from other origins, no framing, and **Trusted Types**: the browser itself refuses to turn a string into HTML or script, so the UI's rule of building pages from elements and text is enforced rather than only followed. API responses get a policy that renders nothing, even if opened directly; the setup page's one stylesheet is allowed by its hash.
- Cross-site requests that change anything are refused by their `Sec-Fetch-Site` and `Origin` headers ([Go's `CrossOriginProtection`](https://pkg.go.dev/net/http#CrossOriginProtection)), on top of `SameSite=Strict` cookies, so another site can't act with your session.
- `Permissions-Policy` turns off every powerful feature but passkeys and the clipboard; `Cross-Origin-Resource-Policy` and `-Opener-Policy` keep other sites from loading responses or reaching into the UI's window; `nosniff` and `no-referrer` throughout; and over HTTPS, `Strict-Transport-Security`.

Tests check each surface's headers, and `TestLayout` runs the UI in Chrome with all of them on, failing on any violation the browser reports.

Passkeys need the UI opened at a host name: on a loopback admin listener that's `http://localhost:{port}`, where page loads at `127.0.0.1` are redirected. Elsewhere, put the admin listener behind a TLS-terminating proxy and set `--admin-origin https://admin.dns.example.com`. Without an origin, browser sign-in is off, and only API tokens work.

### API tokens

On first run the server generates two tokens in the data directory: `admin.token` for everything, and `reader.token` for read-only access (`GET` requests). They're the operator's own credentials, for the CLI on the server and for bootstrapping; they reach every tenant and never expire, so give automation a service account instead. Requests send `Authorization: Bearer <token>`. Browsers' state-changing requests from other origins are refused, whatever they carry. To replace a token, delete its file and restart the server.

### Service accounts

Scripts, home automation, CI jobs, and other servers each get their own identity: a service account. It acts for one tenant, or for the operator, as a `reader` or an `admin`, and sees exactly what a person in that role would.

```sh
doh service-account create "Home Assistant"                    # a reader, with a key that lasts 90 days
doh sa create Backups --admin --secret-file backups.key        # writes the key to a new file, readable only by you
doh sa key rotate "Home Assistant" --grace 1h                  # a new key; the old one works for another hour
doh sa key revoke "Home Assistant" 3f2a9c0d1e4b5a67            # stops a key at once
```

The web UI's Security view does the same.

- **Keys always expire**, within a year (90 days by default). A key's secret, `doh_sa_<key ID>_<256 random bits>`, is shown once and kept only as a SHA-256 hash; the prefix makes a leaked key easy to spot and to scan for.
- **Rotation has no downtime.** Rotating adds a new key and lets the old one keep working for up to a week, so whatever uses it can switch over first.
- **Revocation is immediate.** Revoking a key, or deleting its account, stops it at once. Deleting a tenant deletes its service accounts, and a key whose tenant no longer exists is refused regardless.
- **Service accounts can't manage identities.** Even an admin one can't create sign-in links, list or remove people, or create, rotate, or revoke service account keys or trust rules, its own included. A leaked key can't mint a way back in, or a longer life for itself.
- **Every change is logged**: who created, rotated, or revoked which key, as `admin: service account ...` lines in the server's log.

Service accounts and their key hashes live in `service-accounts.json` in the data directory. Last-used times are kept to the hour, so authenticating rarely writes to disk.

#### Workload identity federation

Automation that already has an identity, such as a GitHub Actions job or a Kubernetes pod, needn't keep a key at all. A service account's **trust rules** say which identity tokens from the workload's own provider it accepts, and the workload exchanges one for a short-lived access token ([OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)). There's no stored secret to leak or rotate.

```sh
doh sa create Deploys --admin --no-key
doh sa trust add Deploys --github-repo octo/app --audience https://admin.dns.example.com \
  --claim repository_id=123456789       # workflows of octo/app on refs/heads/main
doh sa trust add Deploys --issuer https://k8s.example --audience doh \
  --subject system:serviceaccount:ci:deployer
doh sa trust list Deploys
doh sa trust remove Deploys 3f2a9c0d1e4b5a67
```

In a GitHub Actions workflow, request the job's identity token with the rule's audience, exchange it at `POST /api/v1/token`, and send the access token as a bearer token:

```yaml
jobs:
  block:
    runs-on: ubuntu-latest
    permissions:
      id-token: write # lets the job request its identity token
    steps:
      - name: Get a doh access token
        run: |
          id_token=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://admin.dns.example.com" | jq -r .value)
          access_token=$(curl -sSf https://admin.dns.example.com/api/v1/token \
            -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
            -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
            -d audience=SERVICE_ACCOUNT_ID \
            --data-urlencode "subject_token=$id_token" | jq -r .access_token)
          echo "::add-mask::$access_token"
          echo "DOH_TOKEN=$access_token" >> "$GITHUB_ENV"
      - run: |
          curl -sSf -H "Authorization: Bearer $DOH_TOKEN" -d '{"domain":"ads.example"}' \
            https://admin.dns.example.com/api/v1/profiles/home/deny
```

With doh installed, `doh token exchange --account SERVICE_ACCOUNT_ID --subject-token-file id.jwt` does the exchange and prints the access token.

- **A token is accepted only if a rule matches it exactly.** It must be signed with RS256, ES256, or EdDSA by a key its issuer publishes, never HMAC or `none`. Its `iss` must equal the rule's issuer, its `aud` must name the rule's audience, its `sub` must equal the rule's subject, and each `--claim` must equal a string claim. A subject may end in `*` after a `/` or `:`, such as `repo:octo/app:ref:refs/heads/*`, but not so early that it matches a whole namespace, such as `repo:*`. The token must have an `exp`, its `nbf` and `iat` are honored, with 30 seconds' leeway, and it may be valid for at most a day.
- **Pin what can't be renamed.** GitHub repository and owner names can be reused after a rename or deletion, so add `--claim repository_id=...` (or `repository_owner_id`), which GitHub never reuses.
- **The exchange names the account.** Its `audience` is the service account's ID, and only that account's rules are tried, at most five. Refusals are all `invalid_grant`, whatever failed, so they reveal nothing, including whether the account exists; the reason is in the server's log, as `admin: token exchange refused`. A client whose exchanges keep failing is slowed down: after twenty failures, one try every ten seconds (`429 Too Many Requests`).
- **Keys come only from where you said.** By default, the issuer's [OpenID Connect discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) document, at `<issuer>/.well-known/openid-configuration`, names its keys, which must be on the issuer's host; set `--jwks-url` for providers whose keys are elsewhere, such as Google's. Headers in the token itself, such as `jku`, are ignored. Discovery is done once per issuer while the server runs; keys are cached for an hour, refetched at most once a minute for an unknown key ID, and the last good set is used for up to a day if the provider is unreachable. Tenants' rules must use HTTPS; the operator's may also use HTTP to a loopback address.
- **Access tokens are short-lived.** They're `doh_at_<256 random bits>`, last 15 minutes by default (1 minute to an hour, with `--token-lifetime`), and act exactly as the service account would, including that they can't manage people, keys, or trust rules. They're kept only in memory, as SHA-256 hashes, so a restart ends them all, by design; exchange again. At most 10,000 are kept at once, forgetting the oldest beyond that.
- **Revocation is immediate.** Removing a rule, or deleting its account or tenant, stops the access tokens it issued at once. Adding and removing rules, and each exchange, are logged.

#### Binding credentials with DPoP

On its own, a key or an access token is a bearer credential: whoever copies it, from a CI log, a backup, or a config file, can use it. [DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) (RFC 9449) binds it to a private key the client holds instead. Every request then also carries a **proof**, a short-lived JWT signed by that key for that request's method and URL, so a copied credential is useless without the key, and a captured request can't be replayed or redirected to another endpoint.

```sh
doh sa key add CI --dpop --secret-file ci.key      # ci.key holds the secret, ci.key.dpop its new P-256 private key
doh sa create Backups --admin --dpop --secret-file backups.key
doh status --token-file ci.key                     # finds ci.key.dpop beside it, and signs each request
DOH_TOKEN="$(cat ci.key)" DOH_DPOP_KEY_FILE=ci.key.dpop doh status
doh sa key rotate CI --secret-file ci-2.key        # a bound key's replacement is bound too, to a new key
doh sa trust add Deploys --github-repo octo/app --audience https://admin.dns.example.com --require-dpop
```

- **Keys are made where they're used.** `--dpop` makes an ECDSA P-256 key on the machine running `doh`, sends only its [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html) thumbprint (`jkt`) to the server, and writes the secret to `--secret-file` and the private key, as a PEM `PRIVATE KEY` (PKCS #8), to the file beside it with `.dpop` appended. Both are new files, readable only by you; existing files are never overwritten. `doh sa list` marks bound keys `(DPoP)`.
- **Every client command signs.** `--dpop-key FILE` (`DOH_DPOP_KEY_FILE`) names the key; without it, a `--token-file`'s `.dpop` sibling is used if there is one. Keys may be PKCS #8 or SEC 1 (`EC PRIVATE KEY`, as `openssl ecparam` writes) PEM: ECDSA P-256, Ed25519, or RSA of at least 2,048 bits.
- **A bound credential needs the DPoP scheme.** Requests send `Authorization: DPoP <credential>` and the proof in a `DPoP` header ([RFC 9449, Section 7.1](https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1)). A bound credential sent as a bearer token is refused, and so is an unbound one sent with the DPoP scheme. Unbound keys, access tokens, and the operator's tokens work as bearer tokens, as before.
- **Proofs are checked in full** ([Section 4.3](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.3)): `typ` must be `dpop+jwt`; it must be signed with ES256, EdDSA, or RS256, never `none` or HMAC, by the public key in its own `jwk` header, which must have no private parts and the credential's thumbprint; `htm` must be the request's method and `htu` its URL without the query; `iat` must be within a minute of the server's clock, either way; `ath` must be the SHA-256 of the credential; and its `jti` must be new: each proof is accepted once. The server remembers up to 50,000 proofs per replay cache for those two minutes, and refuses new ones beyond that rather than forget any; token exchanges have a cache of their own. Proof verification is [`picatz/jose`](https://github.com/picatz/jose)'s `dpop` package.
- **Refusals say little.** They're `401` with `WWW-Authenticate: DPoP error="invalid_token"` (the wrong scheme, or an unknown credential) or `error="invalid_dpop_proof"` (anything wrong with the proof), and the algorithms accepted; which check failed is only in the server's log, as `admin: credential refused`. A bound key's last use is recorded only once its proof is accepted.
- **Behind a proxy, set `--admin-origin`.** A proof names the URL its client used, which a TLS-terminating proxy hides from the server. With `--admin-origin`, `htu` must be one of those origins with the request's path, which the proxy must forward unchanged; requests to a loopback address, such as through an SSH tunnel, may also name the address they were sent to. Without `--admin-origin`, `htu` must match the request's own `Host`, and `https` only if it came over TLS.
- **Exchanged tokens can be bound too.** A token exchange that carries a proof gets an access token bound to the proof's key, with `"token_type": "DPoP"` ([Section 5](https://www.rfc-editor.org/rfc/rfc9449.html#section-5)); `doh token exchange --new-dpop-key FILE` makes a key for it, or `--dpop-key` uses one. A rule added with `--require-dpop` refuses exchanges without a proof (`400 invalid_dpop_proof`), so none of its access tokens is a bearer token. The proof is checked only after the identity token is accepted. DPoP protects the access token, not the identity token: whoever has a workload's identity token can sign a proof of their own, so rules must still be as narrow as the provider allows.
- **Older versions can't read bound keys.** Bound keys and `--require-dpop` rules add `jkt` and `require_dpop` fields to `service-accounts.json`, which versions of doh before them refuse to load, since they reject unknown fields. To downgrade, revoke bound keys and remove such rules first.

In a GitHub Actions workflow with doh installed, bind the job's access token to a key made for the job, which never leaves the runner:

```yaml
jobs:
  block:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    env:
      DOH_ADDR: https://admin.dns.example.com
    steps:
      - name: Get a DPoP-bound doh access token
        run: |
          curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://admin.dns.example.com" | jq -r .value > "$RUNNER_TEMP/id.jwt"
          access_token=$(doh token exchange --account SERVICE_ACCOUNT_ID \
            --subject-token-file "$RUNNER_TEMP/id.jwt" --new-dpop-key "$RUNNER_TEMP/dpop.pem")
          echo "::add-mask::$access_token"
          echo "DOH_TOKEN=$access_token" >> "$GITHUB_ENV"
          echo "DOH_DPOP_KEY_FILE=$RUNNER_TEMP/dpop.pem" >> "$GITHUB_ENV"
      - run: doh deny ads.example --profile home # signs a proof with the job's key
```

Without doh, any RFC 9449 client works: make a P-256 key (`openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`), send its JWK thumbprint as `{"jkt": "..."}` when adding a key (`POST /api/v1/service-accounts/{id}/keys`) or put a proof on the token exchange, and sign a fresh proof for every request, with a `jti`, `htm`, `htu`, `iat`, and `ath`. In Go, [`internal/client`](../internal/client/client.go)'s `Client.DPoP` does this for every call.

### Using the API

The API is documented in [`internal/api`](../internal/api/api.go). Policy changes are conditional on the `ETag` with `If-Match`, so two people editing at once can't overwrite each other's changes (`412 Precondition Failed`). Profiles are changed with JSON merge patches.

The client commands (`doh status`, `profile`, `allow`, `deny`, `log`, `explain`, `setup`, `people`, `service-account`, `token`, `alerts`, `ui`) read `DOH_ADDR` (default `http://127.0.0.1:9090`), `DOH_TOKEN` or `DOH_TOKEN_FILE` (default: the admin token in the default data directory), and for [bound credentials](#binding-credentials-with-dpop), `DOH_DPOP_KEY_FILE`. They refuse to send a token over plain HTTP to anything but a loopback address.

> [!WARNING]
> The admin listener also serves metrics and profiling. On a loopback listener that isn't published with `--admin-origin`, profiling stays open to the machine's own users, so `go tool pprof` works; once published, `/debug` needs the operator's credentials. Metrics stay open for scrapers. Treat both tokens, and service account keys, as secrets.

## Reliability

DNS failing is the network failing, so the server tries hard not to:

- **Upstreams answer in a race, not a queue.** They're asked in order of preference, but if one hasn't answered after 300 milliseconds, or fails, the next is asked too, and the first answer wins ([RFC 8305](https://www.rfc-editor.org/rfc/rfc8305.html) style). An upstream that fails twice in a row is asked last, with a backoff from five seconds to five minutes, until it answers again. `doh status` shows each upstream's health.
- **Stale answers beat no answers.** If every upstream fails, names resolved in the last day are answered from the cache ([RFC 8767](https://www.rfc-editor.org/rfc/rfc8767.html)), with a 30-second TTL so clients come back soon, and an [Extended DNS Error](https://www.rfc-editor.org/rfc/rfc8914.html#section-4.4) saying so. They're logged with reason `stale`, and counted in `doh_stale_answers_total`.
- **Lists and policies keep working offline.** Blocklists are cached on disk and kept if a refresh fails; a policy followed from another server is cached too.

## Sharing a server

One server can serve several households, each managing its own profiles, devices, query log, and people, without seeing or affecting anyone else's. Each household is a **tenant**; profiles without a tenant belong to the server's **operator**.

```console
$ doh tenant create smiths --name "The Smiths" --network 192.168.10.0/24
$ doh tenant invite smiths
https://admin.dns.example.com/#signin=…
```

The invitation signs in the tenant's first admin. They add a passkey, create profiles, connect devices, and invite others in their household, with `doh ui` style links of their own. What they can't do is bounded by the operator, since their profiles run on someone else's server:

| A tenant's profiles… | Because |
| --- | --- |
| select clients by address only within the tenant's `networks`, which can't overlap other tenants' | Otherwise one tenant could claim `0.0.0.0/0` and capture everyone's plain-DNS clients. Without networks, devices select profiles by DoH path or host name only. |
| use preset blocklists only, unless the operator sets `custom_lists`, which allows HTTPS URLs, never files or plain HTTP | The server downloads lists, so arbitrary locations would let a tenant read the server's files or reach its private network. |
| number at most `max_profiles` (20 by default) | Bounds what one tenant can make the server do. |

Tenants see only their own profiles, query log entries, stats, people, and setup instructions. Everything else, including other tenants' profiles, looks like it doesn't exist. The raw policy, tenant management, server status details (traffic, lists, listeners), and profiling are the operator's alone. The server's own API tokens are operator credentials; tenants sign in with links and passkeys, and give their automation [service accounts](#service-accounts) of their own. Each tenant's passkey requirement is its own, so a newly invited household can sign in with its first link even when the operator uses passkeys.

Profile IDs and device names share one namespace, since they appear in DoH paths and host names, so a tenant can learn that an ID is taken, though not whose it is.

Removing a tenant (`doh tenant delete`) requires removing or moving its profiles first, and removes its people.

## Following another server's policy

A server can follow another server's policy instead of keeping its own. For example, a Raspberry Pi at home can follow a server in the cloud, so one place manages a family's profiles:

```console
$ doh serve --dns-listen :53 \
    --policy https://doh.example.com:9090/api/v1/policy \
    --policy-token-file /etc/doh/reader.token
```

The follower polls every minute (`policy.refresh` in the config file) with `If-None-Match`, applies each new policy, and caches it in its data directory, so it starts with the last known policy if the other server is down. Its own API is read-only. The URL must use HTTPS unless it's on a loopback address, and redirects aren't followed, so the token can't be sent elsewhere. Use the other server's **reader** token.

Each server keeps its own query log and queries its own upstreams. Without `--policy`, a server is fully independent.

## Troubleshooting

`doh doctor` checks that a device's DNS actually reaches doh:

```console
$ doh doctor
✓ system nameservers: 192.168.1.10
✓ 192.168.1.10:53 is answered by doh (profile=default, device=laptop, client=192.168.1.23)
✓ Firefox will use this network's resolver
✓ admin API reachable at http://127.0.0.1:9090
```

It asks each nameserver who it is with a CHAOS `TXT` query for `id.server` ([RFC 4892](https://www.rfc-editor.org/rfc/rfc4892.html#section-2)). doh answers with the profile and device the query matched, which you can also see with `dig CH TXT id.server @192.168.1.10`.

Common findings:

- **Tailscale MagicDNS is handling DNS** (`100.100.100.100`). While Tailscale runs, it sends the device's queries to MagicDNS first, which can bypass doh. Add doh as a global nameserver with **Override local DNS** in the Tailscale admin console, or run `tailscale set --accept-dns=false` on the device. This is easy to forget, since it applies even when you don't think of Tailscale as running.
- **systemd-resolved's stub resolver** (`127.0.0.53`). It forwards elsewhere; `resolvectl status` shows where.
- **macOS** doesn't always use `/etc/resolv.conf`; `scutil --dns` shows the resolvers it does use, including VPNs'.

## Limits

- Detection is heuristic. Look-alike checks cover internationalized names only, not ASCII typosquats such as `paypa1.com`. Tunneling detection can flag security software that queries hashes over DNS; allow its domains if so.
- Newly registered domain checks depend on registries' RDAP services. Many country-code TLDs (such as `.io`, `.sh`, `.de`, and `.co`) have none, so their names are never blocked as new. Registries see which domains are looked up, though not who asked, and each domain is looked up at most about once a month.
- There's no "newly active" signal: a long-registered domain that has just started resolving isn't detected.
- Blocking works on names. Apps that hard-code IP addresses, or use encrypted DNS services that aren't blocked, aren't filtered; bypass protection and the `bypass-services` list make that harder, not impossible.
- Unbound service account keys and access tokens, and the operator's admin and reader tokens, are bearer credentials: whoever holds one can use it until it expires or is revoked, so an unbound access token copied from a CI log works until it expires, 15 minutes by default. [Bound](#binding-credentials-with-dpop) keys and access tokens need their DPoP key too, but the two together are as good as an unbound key: keep the key file as private as the secret, and make keys on the machine that uses them. The operator's tokens can't be bound, and binding is opt-in: nothing yet requires every key of an account or tenant to be bound.
- DPoP proofs are fresh to within a minute either way of the server's clock, and each is accepted once by the server process that saw it; the server doesn't hand out nonces ([RFC 9449, Section 8](https://www.rfc-editor.org/rfc/rfc9449.html#section-8)), so a client with a fast clock could pre-sign proofs up to a minute ahead. Replay caches are in memory, per process, so a proof captured just before a restart could be replayed once in what's left of its minute, with the credential it was sent with; bound access tokens end with the restart anyway. Proofs cover the method and URL, not the query, headers, or body ([Section 11](https://www.rfc-editor.org/rfc/rfc9449.html#section-11)); TLS still protects those.
- Workload identity federation trusts the identity provider: anyone who can get it to issue a token with a rule's issuer, audience, subject, and claims can act as the account. Write rules as narrowly as the provider allows. Access tokens don't survive a restart, and a provider's rotated keys are picked up only when a token names a key the cached set lacks, or within the hour.
- Profile IDs in DoH paths are identifiers, not credentials. To keep strangers off a public server, remove the `default` profile and use unguessable profile IDs, or restrict who can reach it.
- Alerts are best effort. Deliveries waiting or being retried are lost on restart, and when too many queries arrive at once for alerts to keep up, the excess are skipped (and counted in the server's log) rather than slow down answering. Coalescing, bursts, quiet hours' held alerts, failing-lookup windows (one-minute buckets, so "five minutes" is four to five), and recent deliveries are kept in memory, so a restart starts them afresh.
- Alerts come from the query log: profiles with logging off, and servers run with `--no-query-log`, get no threat, new-device, or failing alerts. A threat repeated within the hour is in the query log, not another alert.
- New devices are as distinct as their names and addresses: behind NAT, a household is one device; a device that changes its address (private Wi-Fi addresses, IPv6 privacy addresses) can look new; a hostname is whatever the device calls itself. On a server open to the internet, every new client address is a new device, so the operator may want `new-device` off.
- Webhook secrets are kept in `alerts.json`, readable only by the server's user, since doh needs them to sign. Tenants' deliveries connect directly, never through `HTTPS_PROXY`; the operator's https deliveries use it.
- Push subscriptions' keys and email unsubscribe tokens are kept in `alerts.json` too, and the VAPID key in `push-vapid.pem`. Push services see when a browser is sent something, and how large it is, though not what. Email goes through the operator's mail server in whatever way it delivers onward; the confirmation and alert rate limits are kept in memory, so a restart resets them.
- Web Push and email are tested against RFC 8291's example, RFC 8292's example token, and a fake SMTP server; delivery through real push services and mail providers hasn't been verified by tests.
- Client addresses identify devices only as well as the network does. Behind NAT, a whole network shares one address; over DoH, use per-device paths instead. Apps on the same device can't be told apart.
