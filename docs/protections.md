# Profiles and protections

`doh serve` applies a **policy** to every query: a set of **profiles**, each the rules for a group of devices. A profile chooses which protections are on, which blocklists apply, which domains are always allowed or denied, and how blocked names are answered. Every decision can be traced, logged, and undone.

- [How a query is decided](#how-a-query-is-decided)
- [Protections](#protections)
- [Blocklists](#blocklists)
- [Profiles and devices](#profiles-and-devices)
- [The policy file](#the-policy-file)
- [Local names and forward zones](#local-names-and-forward-zones)
- [Query log](#query-log)
- [Admin API and web UI](#admin-api-and-web-ui)
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
| 5 | `bypass` | Firefox's DoH canary; with bypass protection, Private Relay and public encrypted DNS. |
| 6 | `tld` | Blocked top-level domains. |
| 7 | `list` | Blocklists, unless any of the profile's lists has an exception for the name. |
| 8 | `homograph` | Look-alike internationalized names. |
| 9 | `tunneling` | Data smuggled through DNS. |
| 10 | `newly-registered` | Domains registered recently. |
| 11 | `safe-search` | Safe search hosts for search engines and YouTube. |
| 12 | `cname` | Answers whose CNAME targets are denied, under a blocked TLD, or on a blocklist. |
| 13 | `rebinding` | Answers that point public names at local addresses. |

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

## Query log

Every query is logged with its profile, device, client, name, type, outcome, reason, matching rule and list, answers, upstream, and duration. The newest 50,000 entries are kept in memory to search, and every entry is written to a daily file in `querylog/` in the data directory, which is reloaded on restart and deleted after `--query-log-retention` (seven days by default). Turn logging off for a profile with `"logging": {"disabled": true}`, or for the whole server with `--no-query-log`; queries are still counted in metrics.

```console
$ doh log --blocked -n 5
TIME      CLIENT          STATUS   TYPE  NAME                      REASON
18:53:08  living-room-tv  blocked  A     ads.example.net           list (hagezi-normal)
$ doh log -f --profile kids         # follow live
$ doh log --json -q google | jq .   # JSON lines
```

## Admin API and web UI

With `--admin-listen`, the admin listener serves a web UI at `/` and a JSON API at `/api/v1`, alongside metrics and profiling. On first run the server generates two tokens in the data directory: `admin.token` for everything, and `reader.token` for read-only access (`GET` requests). Requests need `Authorization: Bearer <token>`.

```console
$ doh serve --dns-listen :53 --admin-listen localhost:9090
$ doh ui
http://127.0.0.1:9090/#token=doh_admin_…
```

`doh ui` prints a sign-in link. The token is in the URL fragment, which browsers never send to the server, so it doesn't end up in logs. The UI toggles every protection and list, edits allow and deny lists, devices, and rewrites, searches and follows the query log, allows or blocks a name from any log entry in one click, and explains any decision.

The API is documented in [`internal/api`](../internal/api/api.go). Policy changes are conditional on the `ETag` with `If-Match`, so two people editing at once can't overwrite each other's changes (`412 Precondition Failed`). Profiles are changed with JSON merge patches.

The client commands (`doh status`, `profile`, `allow`, `deny`, `log`, `explain`, `ui`) read `DOH_ADDR` (default `http://127.0.0.1:9090`), and `DOH_TOKEN` or `DOH_TOKEN_FILE` (default: the admin token in the default data directory). They refuse to send a token over plain HTTP to anything but a loopback address.

> [!WARNING]
> The admin listener also serves profiles and process details. Keep it on a loopback or private address, or behind a TLS-terminating proxy you control, and treat both tokens as secrets.

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
- Profile IDs in DoH paths are identifiers, not credentials. To keep strangers off a public server, remove the `default` profile and use unguessable profile IDs, or restrict who can reach it.
- Client addresses identify devices only as well as the network does. Behind NAT, a whole network shares one address; over DoH, use per-device paths instead. Apps on the same device can't be told apart.
