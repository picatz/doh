# Status

Where doh stands, how each part is verified, what it doesn't do yet, and
what's worth doing next. Keep it true: update it with the change that
makes it stale.

## What's here

| Area | What it does | Verified by |
| --- | --- | --- |
| Resolving | DoH ([RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html)), DoT ([RFC 7858](https://www.rfc-editor.org/rfc/rfc7858.html)), DoQ ([RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html), experimental), and plain DNS; hedged upstreams, caching, serve-stale ([RFC 8767](https://www.rfc-editor.org/rfc/rfc8767.html)), padding, Extended DNS Errors | unit and integration tests; DoQ interop with public resolvers is opt-in (`DOH_LIVE_TESTS=1`) |
| Protection | threat intelligence and other lists (security lists checked every 2 hours, others daily, by conditional request), look-alike names, typosquatting, machine-generated domains, Google Safe Browsing (opt-in, v5 local lists), rebinding, tunneling, newly registered domains (RDAP), bypass methods, safe search, blocked TLDs, CNAME checks | `internal/filter` tests, check by check, with negative tests on popular domains, brands' own domains, CDN names, and IDNs; fuzz targets for the scorers and parsers; `testing/synctest` for list refresh and Safe Browsing's waits; mutation checks that the tests catch a broken detector; `doh explain` shows every decision. Safe Browsing is tested against an in-process fake of the API, never Google (see below) |
| Profiles | per-device policy by DoH path, host name, or address; 93 apps blockable by name; schedules in each profile's time zone; rewrites; local zones | `internal/policy`, `filter`, and `services` tests |
| Device setup | instructions for 17 platforms in 7 groups (phones and tablets, computers, TV and streaming, consoles, smart home, browsers, whole network), each with its protection level, a check, and how the device is identified; generated files: Apple configuration profiles (DoH, DoT, locked), a Windows PowerShell script, a systemd-resolved drop-in, and an OpenWrt script, from the admin API and setup links | golden tests of every file; configuration profiles parsed back with `internal/plist`; the OpenWrt script parsed by `dash -n`; the PowerShell script checked for ASCII, no network fetching, and `ShouldProcess` before every change, but not run or parsed by PowerShell here; negative tests: other tenants' profiles, expired links, the link's device overriding the query, invalid devices and variants. No real devices were tried: menu paths, Apple TV and Vision Pro installs, Android TV's adb settings, and router steps are documented, not verified |
| Visibility | Activity (query log) with device names learned from the network, stats, a per-hour timeline, live streaming | `internal/querylog` and `hostnames` tests (with `testing/synctest`) |
| Alerts | threats blocked, new devices, failing lookups, and lists that didn't load, sent as Web Push notifications to browsers (encrypted per [RFC 8291](https://www.rfc-editor.org/rfc/rfc8291.html), signed with VAPID, [RFC 8292](https://www.rfc-editor.org/rfc/rfc8292.html), no push vendor account), to email addresses that confirm with a single-use code, to [ntfy](https://ntfy.sh), or to webhooks signed as [Standard Webhooks](https://www.standardwebhooks.com/) describes; repeats coalesced, bursts summarized, quiet hours in each tenant's time zone; set up in the web UI's Security view, with `doh alerts`, or with the API | RFC 8291's Appendix A reproduced byte for byte, every intermediate value checked, and RFC 8292's example token verified; a fake push service that checks each VAPID token and decrypts each message; a fake SMTP server for STARTTLS required, certificate checks, AUTH PLAIN, temporary and permanent refusals, and encoded non-ASCII subjects; negative tests for push endpoints off the allowlist (and a tenant's resolving privately), forged, expired, replayed, and other tenants' confirmation codes, forged unsubscribe tokens, and every rate limit; mutation checks that the tests catch a broken encryption, allowlist, or confirmation; `internal/alerts` tests with `testing/synctest` (coalescing, bursts, the learning period, failing thresholds, quiet hours across midnight), the specification's signature test vector, and negative tests: tenants never get others' or the operator's alerts, tenants' deliveries to loopback, private, link-local, and metadata addresses are refused when added and when dialed, redirects aren't followed, secrets are shown once, readers and service accounts are refused, other tenants' alerts read as not found, a full queue drops instead of blocking |
| Sharing | tenants (households, customers) with their own profiles, people, and service accounts, seeing nothing of each other | negative tests: other tenants' resources read as not found |
| Identity | passkey sign-in (WebAuthn, written here), single-use links, service accounts with expiring, rotatable keys, workload identity federation (OIDC token exchange, [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html)) so automation needs no stored secret, DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)) to bind keys and exchanged tokens to a client's key, setup links for devices, shown as QR codes (an ISO/IEC 18004 encoder written here, drawn in doh's colors with its donut) | negative tests: forged, expired, replayed, revoked, cross-tenant; for federation, wrong issuer, audience, subject, or claims, `alg: none`, HMAC with a public key, unknown keys, over-long tokens, and rate limits, with a mutation check that the tests catch a broken matcher; for DPoP, no proof, the Bearer scheme, another key, wrong method or URL (scheme, host, port, path, origin behind a proxy), stale or future `iat`, replayed `jti`, missing or wrong `ath`, `alg: none`, HMAC, disallowed algorithms, malformed proofs, wrong `typ`, and private keys in `jwk`, with mutation checks that the tests catch a broken `ath`, `jkt`, replay, or scheme check; every QR version, level, and mask, and the branded code as drawn, donut and all, is decoded by ZBar, an independent decoder, in CI; a test checks every module's color in the drawing against the code |
| Web UI | its own identity ([design.md](design.md)); installable as an app (manifest, icons drawn from the mark by `go generate`, a service worker that shows notifications and caches nothing); adaptive shell for phones, tablets, and desktops; ⌘K; the Overview ring; light, dark, high-contrast, and forced colors; keyboard and screen reader use | Go tests on markup and scripts' safety (CSP, no unsafe DOM, one Trusted Types policy, only for the service worker's URL), the committed icons regenerated and compared byte for byte, the manifest's icons checked against their sizes, WCAG contrast computed from the color tokens, and node tests for each module; `TestLayout` drives Chrome over a real server, through every view at 320 to 1440 pixels wide in both themes, and fails on anything that scrolls sideways or sticks out, a control under 24 pixels to tap, or a console error (it runs where Chrome and Node are, as in CI) |
| Configuration profiles | Apple configuration profiles for encrypted DNS, signed (CMS SignedData, [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652.html), an encoder written here) with `--profile-signing-cert`, the TLS certificate, or the ACME certificate, else unsigned, as the setup API's `signing` says | `internal/cms` and `internal/serve` tests: OpenSSL (`openssl cms -verify`, an independent implementation) verifies ECDSA and RSA signatures against a test root and outputs the exact profile, and a decoder written apart from the encoder checks the structure; negative tests: tampered content, an unrelated root, mismatched or Ed25519 keys refused at startup, expired certificates warned about; mutation checks that a wrong digest, wrong signed attributes, or changed content fail OpenSSL. Not checked on a device: that iPhones and Macs show **Verified** |
| Releases | static, reproducible builds for nine platforms, with SHA-256 sums and signed build provenance | `make dist` twice gives identical sums; `gh attestation verify` |

Every change runs `gofmt`, `go vet ./...`, and `go test -race ./...` in CI
(`make check` locally), against the oldest supported Go and the latest.

## Fuzzing

Every parser of untrusted input has a native Go fuzz target, with seeds
and invariants beyond "doesn't panic". `make fuzz` runs each for
`FUZZTIME` (10s by default); inputs that once failed are kept in each
package's `testdata/fuzz` and run with every `go test`. The audit of
November 2026 ran each new target for 60 seconds (30 for `doq` after its
fix) on 2 workers, locally:

| Untrusted input | Fuzz targets | Run | Findings |
| --- | --- | --- | --- |
| DoH GET and POST requests (`pkg/doh`) | `FuzzHandler_Get`, `FuzzHandler_Post`: 200 exactly for one-question queries, answers that unpack and match the query's ID | 60s each | none |
| DoQ streams (`internal/doq`) | `FuzzReadMessage`: exactly one length-prefixed message, framing round-trips | 60s, then 30s | miekg/dns v1.1.73 packs some NSEC3 records it unpacked into bytes it can't unpack; a library asymmetry, not a doh bug; the target now checks framing only, and keeps the input as a seed |
| Query names and types from clients, upstream answers (`internal/filter`) | `FuzzCheck` (decisions are well-formed, blocks and rewrites pack), `FuzzCheckResponse` (a public name answered with 127.0.0.1 is always blocked), `FuzzHomograph`, `FuzzRegistrable` | 60s each | none |
| Blocklists: hosts, Adblock Plus, domain lists (`internal/blocklist`) | `FuzzRules` (normalized domains, a built list blocks what was parsed), `FuzzParseSource` | 60s each | none |
| Policy JSON from files, the API, and followed servers (`internal/policy`, `internal/filter`) | `FuzzUnmarshal` (round-trips), `FuzzCompile` (every valid policy compiles), `FuzzNormalizeDomain`, `FuzzParsePrefix`, `FuzzParseClock` | 60s each | none |
| RDAP bootstrap and domain responses (`internal/rdap`) | `FuzzParseBootstrap`, `FuzzParseRegistration` (plausible dates only), `FuzzNormalize` | 60s each | none |
| Identity tokens for token exchange (`internal/federation`) | `FuzzVerify`: only tokens the provider signed, with the rule's claims, are accepted | 60s | none |
| DPoP proofs and Authorization headers (`internal/serve`) | `FuzzVerifyProof` (only the bound key's proofs, each once), `FuzzCredential` | 60s each | none |
| Service account secrets (`internal/serviceaccount`) | `FuzzLookup`: only the exact secret finds its key | 60s | none |
| Alert destinations, webhook signatures, alert settings (`internal/alerts`) | `FuzzCheckURL` (tenants reach only public https), `FuzzVerify` (only what was signed verifies), `FuzzSettingsNormalize` | 60s each | none |
| DHCP leases, device names, routes (`internal/hostnames`) | `FuzzParseLeases`, `FuzzNormalize` (always a valid device name), `FuzzParseRoutes` | 60s each | none |
| Activity filters and page tokens (`internal/querylog`) | `FuzzParseFilter`, `FuzzDecodeToken` | 60s each | none |
| Server-sent events and DPoP key files (`internal/client`) | `FuzzEvents`, `FuzzParseDPoPKey` | 60s each | none; a lone carriage return isn't treated as a line ending, which doh's server never sends |
| Upstream URLs (`internal/upstream`) | `FuzzParse` | 60s | none |
| Configuration profiles (`internal/plist`) | `FuzzMarshal`: well-formed XML whatever the strings, which read back exactly | 60s | none |
| QR codes (`internal/qr`) | `FuzzEncode`: smallest version, finder patterns, deterministic, well-formed SVG | 60s | an SVG label with invalid UTF-8 or control characters made malformed XML; labels are now escaped with `encoding/xml`, replacing such characters (doh's own labels were never affected) |
| Signed profiles (`internal/cms`) | `FuzzSign`: decodes back to the content and time, and verifies | 60s | none |
| WebAuthn, COSE keys, CBOR (`internal/webauthn`, `internal/cose`) | 8 and 2 existing targets | seeds, and 4s each where reached | none |
| Strict JSON (`internal/strictjson`) | 3 existing targets | 4s, `FuzzUnmarshalExtra` 20s | the oracle of `FuzzUnmarshalExtra` mistook `"aud":[]`, dropped by `omitempty`, for a change; it now compares as JSON |

Not fuzzed here, since they're third-party, trusted, or don't parse:
DNS wire format itself (miekg/dns, reached through the targets above), JWS
and JWT (picatz/jose, reached through `FuzzVerify` and `FuzzVerifyProof`),
CBOR (picatz/cbor, through the WebAuthn and COSE targets), the server's
own config file and the state files it writes, `/etc/resolv.conf` for
`doh doctor`, and session cookies, which are only hashed and looked up.

## Threat detection measurements

Measured on 2026-11-02 against the [Tranco list](https://tranco-list.eu/list/V354N) V354N. Popular isn't the same as legitimate: Tranco ranks some malicious and machine-generated domains too, so "flagged popular domains" overstates false positives in some places and the brands' look-alikes in it are often real typosquats.

- **Typosquatting** flags 181 of the top 1,000,000 domains (0.018%). The brand list and its exceptions were tuned on this same list, so this is an optimistic figure for false positives, not a held-out one. Reviewing what's flagged, most are typo registrations (`faceboook.com`, `instgram.com`, `micosoft.icu`), and some are legitimate businesses a letter from a brand (`goodie.pl`, `sportify.tw`, `netfilm.world`), which is why it's off by default. Of the top 10,000, two are flagged (`oneidrive.org`, `googll.store`), whose owners aren't known. It takes about 0.1 to 1.2 µs a name, without allocating, once the registrable domain is known.
- **Machine-generated domains**, at the default threshold, flag 4 of the 4,852 scored labels (0.08%) among the top 10,000 domains, which the model wasn't trained on (it learned from ranks 10,001 to 40,000), and 0.74% of scored labels past rank 40,000, most of which are random strings themselves. Recall on names from reimplemented generators (constructions after published analyses, not checked against captured samples): CryptoLocker-like 47%, Ramnit-like 44%, Necurs-like 53%, Conficker-like 9% (most are too short to score), MD5-hex (Bamital-like) and base-36 (newGOZ-like) 100%, pronounceable (Simda-like) 0%, and dictionary words (Suppobox-like) 0%. Precision, if as many generated names as popular ones were queried, is 0.998. Lower thresholds catch more and flag more: `TestDGA_Curve` prints the trade-off. It takes 0.2 to 0.8 µs a label, without allocating.
- **Google Safe Browsing** is implemented against the v5 API's published protocol buffer definitions (`google/security/safebrowsing/v5/safebrowsing.proto`), the reference documentation, and Firefox's v5 client (for the query parameters' encoding), and tested only against an in-process fake. What hasn't been verified against Google: that the API accepts the key in the `X-Goog-Api-Key` header, the exact base64 form it expects for `version` and `hashPrefixes`, and that the checksum is computed as the docs describe (SHA-256 over the sorted 4-byte prefixes). A mismatch would show as update or search errors in the log, and names would be allowed.
- **List refresh**: checked live once that GitHub's raw host, which serves the HaGeZi presets, answers `If-None-Match` with `304 Not Modified` and an empty body.

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
- **Signed profiles show as verified only while their certificate is
  valid and trusted.** A Let's Encrypt certificate lasts 90 days or less,
  and a downloaded profile keeps the signature it was downloaded with;
  installed profiles keep working either way. See
  [protections.md](protections.md#signed-configuration-profiles).
- **Detection is heuristic,** names-based, and as good as its lists; see
  the Limits in [protections.md](protections.md#limits).

## Next

In rough order of what it would mean for people using doh:

1. **Notifications in the Security view:** wire `push.js` into the
   redesigned UI, and check delivery through Google's, Mozilla's, and
   Apple's push services on real devices.
2. **Safe Browsing against the live API,** then persisting its lists
   across restarts, and the web UI's presets choosing the new
   protections (they're toggles in the Security view now).
3. **Shared state for replicas:** sessions, setup links, stats, DPoP
   replay caches, and alerts' windows behind an interface with a SQLite
   (single node) and a networked backend.
4. **DoH over HTTP/3,** tracked in
   [picatz/doh#73](https://github.com/picatz/doh/issues/73), waiting on
   Go's own HTTP/3.
4. **SBOMs for releases,** published and attested next to each binary,
   are planned.
