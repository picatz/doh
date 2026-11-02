# Status

Where doh stands, how each part is verified, what it doesn't do yet, and
what's worth doing next. Keep it true: update it with the change that
makes it stale.

## What's here

| Area | What it does | Verified by |
| --- | --- | --- |
| Resolving | DoH ([RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html)), DoT ([RFC 7858](https://www.rfc-editor.org/rfc/rfc7858.html)), DoQ ([RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html), experimental), and plain DNS; hedged upstreams, caching, serve-stale ([RFC 8767](https://www.rfc-editor.org/rfc/rfc8767.html)), padding, Extended DNS Errors | unit and integration tests; DoQ interop with public resolvers is opt-in (`DOH_LIVE_TESTS=1`) |
| Protection | threat intelligence and other lists, look-alike names, rebinding, tunneling, newly registered domains (RDAP), bypass methods, safe search, blocked TLDs, CNAME checks | `internal/filter` tests, check by check; `doh explain` shows every decision |
| Profiles | per-device policy by DoH path, host name, or address; 93 apps blockable by name; schedules in each profile's time zone; rewrites; local zones | `internal/policy`, `filter`, and `services` tests |
| Device setup | instructions for 17 platforms in 7 groups (phones and tablets, computers, TV and streaming, consoles, smart home, browsers, whole network), each with its protection level, a check, and how the device is identified; generated files: Apple configuration profiles (DoH, DoT, locked), a Windows PowerShell script, a systemd-resolved drop-in, and an OpenWrt script, from the admin API and setup links | golden tests of every file; configuration profiles parsed back with `internal/plist`; the OpenWrt script parsed by `dash -n`; the PowerShell script checked for ASCII, no network fetching, and `ShouldProcess` before every change, but not run or parsed by PowerShell here; negative tests: other tenants' profiles, expired links, the link's device overriding the query, invalid devices and variants. No real devices were tried: menu paths, Apple TV and Vision Pro installs, Android TV's adb settings, and router steps are documented, not verified |
| Visibility | Activity (query log) with device names learned from the network, stats, a per-hour timeline, live streaming | `internal/querylog` and `hostnames` tests (with `testing/synctest`) |
| Alerts | threats blocked, new devices, failing lookups, and lists that didn't load, sent as Web Push notifications to browsers (encrypted per [RFC 8291](https://www.rfc-editor.org/rfc/rfc8291.html), signed with VAPID, [RFC 8292](https://www.rfc-editor.org/rfc/rfc8292.html), no push vendor account), to email addresses that confirm with a single-use code, to [ntfy](https://ntfy.sh), or to webhooks signed as [Standard Webhooks](https://www.standardwebhooks.com/) describes; repeats coalesced, bursts summarized, quiet hours in each tenant's time zone; set up in the web UI's Security view, with `doh alerts`, or with the API | RFC 8291's Appendix A reproduced byte for byte, every intermediate value checked, and RFC 8292's example token verified; a fake push service that checks each VAPID token and decrypts each message; a fake SMTP server for STARTTLS required, certificate checks, AUTH PLAIN, temporary and permanent refusals, and encoded non-ASCII subjects; negative tests for push endpoints off the allowlist (and a tenant's resolving privately), forged, expired, replayed, and other tenants' confirmation codes, forged unsubscribe tokens, and every rate limit; mutation checks that the tests catch a broken encryption, allowlist, or confirmation; `internal/alerts` tests with `testing/synctest` (coalescing, bursts, the learning period, failing thresholds, quiet hours across midnight), the specification's signature test vector, and negative tests: tenants never get others' or the operator's alerts, tenants' deliveries to loopback, private, link-local, and metadata addresses are refused when added and when dialed, redirects aren't followed, secrets are shown once, readers and service accounts are refused, other tenants' alerts read as not found, a full queue drops instead of blocking |
| Sharing | tenants (households, customers) with their own profiles, people, and service accounts, seeing nothing of each other | negative tests: other tenants' resources read as not found |
| Identity | passkey sign-in (WebAuthn, written here), single-use links, service accounts with expiring, rotatable keys, workload identity federation (OIDC token exchange, [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html)) so automation needs no stored secret, DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)) to bind keys and exchanged tokens to a client's key, setup links for devices, shown as QR codes (an ISO/IEC 18004 encoder written here, drawn in doh's colors with its donut) | negative tests: forged, expired, replayed, revoked, cross-tenant; for federation, wrong issuer, audience, subject, or claims, `alg: none`, HMAC with a public key, unknown keys, over-long tokens, and rate limits, with a mutation check that the tests catch a broken matcher; for DPoP, no proof, the Bearer scheme, another key, wrong method or URL (scheme, host, port, path, origin behind a proxy), stale or future `iat`, replayed `jti`, missing or wrong `ath`, `alg: none`, HMAC, disallowed algorithms, malformed proofs, wrong `typ`, and private keys in `jwk`, with mutation checks that the tests catch a broken `ath`, `jkt`, replay, or scheme check; every QR version, level, and mask, and the branded code as drawn, donut and all, is decoded by ZBar, an independent decoder, in CI; a test checks every module's color in the drawing against the code |
| Web UI | its own identity ([design.md](design.md)); installable as an app (manifest, icons drawn from the mark by `go generate`, a service worker that shows notifications and caches nothing); adaptive shell for phones, tablets, and desktops; ⌘K; the Overview ring; light, dark, high-contrast, and forced colors; keyboard and screen reader use | Go tests on markup and scripts' safety (CSP, no unsafe DOM, one Trusted Types policy, only for the service worker's URL), the committed icons regenerated and compared byte for byte, the manifest's icons checked against their sizes, WCAG contrast computed from the color tokens, and node tests for each module; `TestLayout` drives Chrome over a real server, through every view at 320 to 1440 pixels wide in both themes, and fails on anything that scrolls sideways or sticks out, a control under 24 pixels to tap, or a console error (it runs where Chrome and Node are, as in CI) |
| Releases | static, reproducible builds for nine platforms, with SHA-256 sums and signed build provenance | `make dist` twice gives identical sums; `gh attestation verify` |

Every change runs `gofmt`, `go vet ./...`, and `go test -race ./...` in CI
(`make check` locally), against the oldest supported Go and the latest.

## Limits

These are also stated where each feature is documented; see
[protections.md, Limits](protections.md#limits).

- **Some credentials are bearer tokens.** The operator's tokens, and
  service account keys and exchanged access tokens that aren't bound with
  DPoP, work for whoever holds them until they expire or are revoked.
  Binding is opt-in per key and per trust rule, and the server issues no
  DPoP nonces, relying on a minute's `iat` window and a per-process replay
  cache. Federation trusts the identity provider, so rules should be as
  narrow as it allows.
- **State is per process.** Sessions, setup links, and stats over the
  in-memory query log live in one process; the policy, people, service
  accounts, and log files are on disk. Running several replicas behind a
  load balancer would need shared storage for these, and for DPoP replay
  caches, which doesn't exist yet. One server comfortably serves a large
  household, school, or small company; past that, scale out with separate
  servers that follow one policy (`--policy`).
- **Alerts are best effort.** Deliveries are retried for under a minute,
  then recorded as failed; pending ones are lost on restart, and under a
  flood of queries some are skipped rather than slow down answering.
  They come from the query log, so profiles that don't log get none.
  Web Push and email are verified against the RFCs' examples, a fake
  push service, and a fake mail server, not yet against real push
  services or mail providers; the web UI's button to subscribe a
  browser is still to be wired into the redesigned Security view.
- **Setup steps are written, not tried on devices.** Device menus vary by
  version and maker; Apple TV needs Apple Configurator or MDM; many TVs,
  consoles, and smart devices only take plain DNS by address, unencrypted on
  the network, and some ignore the network's DNS entirely.
- **Detection is heuristic,** names-based, and as good as its lists; see
  the Limits in [protections.md](protections.md#limits).

## Next

In rough order of what it would mean for people using doh:

1. **Notifications in the Security view:** wire `push.js` into the
   redesigned UI, and check delivery through Google's, Mozilla's, and
   Apple's push services on real devices.
2. **Shared state for replicas:** sessions, setup links, stats, DPoP
   replay caches, and alerts' windows behind an interface with a SQLite
   (single node) and a networked backend.
3. **Signed configuration profiles** for Apple devices, so they don't
   show as unverified.
4. **DoH over HTTP/3,** tracked in
   [picatz/doh#73](https://github.com/picatz/doh/issues/73), waiting on
   Go's own HTTP/3.
