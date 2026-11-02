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
| Visibility | Activity (query log) with device names learned from the network, stats, a per-hour timeline, live streaming | `internal/querylog` and `hostnames` tests (with `testing/synctest`) |
| Sharing | tenants (households, customers) with their own profiles, people, and service accounts, seeing nothing of each other | negative tests: other tenants' resources read as not found |
| Identity | passkey sign-in (WebAuthn, written here), single-use links, service accounts with expiring, rotatable keys, workload identity federation (OIDC token exchange, [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html)) so automation needs no stored secret, setup links for devices | negative tests: forged, expired, replayed, revoked, cross-tenant; for federation, wrong issuer, audience, subject, or claims, `alg: none`, HMAC with a public key, unknown keys, over-long tokens, and rate limits, with a mutation check that the tests catch a broken matcher |
| Web UI | its own identity ([design.md](design.md)); adaptive shell for phones, tablets, and desktops; ⌘K; the Overview ring; light, dark, high-contrast, and forced colors; keyboard and screen reader use | Go tests on markup and scripts' safety (CSP, no unsafe DOM), node tests for each module, and driven in Chromium at three widths in both themes |
| Releases | static, reproducible builds for nine platforms, with SHA-256 sums and signed build provenance | `make dist` twice gives identical sums; `gh attestation verify` |

Every change runs `gofmt`, `go vet ./...`, and `go test -race ./...` in CI
(`make check` locally), against the oldest supported Go and the latest.

## Limits

These are also stated where each feature is documented; see
[protections.md, Limits](protections.md#limits).

- **Credentials are bearer tokens.** Service account keys, exchanged
  access tokens, and the operator's tokens work for whoever holds them
  until they expire or are revoked. They aren't yet bound to a client key
  (DPoP). Federation trusts the identity provider, so rules should be as
  narrow as it allows.
- **State is per process.** Sessions, setup links, and stats over the
  in-memory query log live in one process; the policy, people, service
  accounts, and log files are on disk. Running several replicas behind a
  load balancer would need shared storage for these, which doesn't exist
  yet. One server comfortably serves a large household, school, or small
  company; past that, scale out with separate servers that follow one
  policy (`--policy`).
- **No alerts.** Things that need attention show on the Overview; nothing
  is pushed to anyone yet.
- **Detection is heuristic,** names-based, and as good as its lists; see
  the Limits in [protections.md](protections.md#limits).

## Next

In rough order of what it would mean for people using doh:

1. **Alerts.** Tell a household's admins, by email, a webhook, or a push
   service such as ntfy, when a threat is blocked on their network, a
   device appears, or queries start failing. The Overview's "needs
   attention" items are the starting set.
2. **DPoP** ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)) for
   service accounts and exchanged tokens, so a leaked token is useless
   without its key. [`picatz/jose`](https://github.com/picatz/jose) has
   `dpop`, verifier and client.
3. **QR codes for setup links,** once an encoder is verified against an
   independent decoder in tests.
4. **Shared state for replicas:** sessions, setup links, and stats behind
   an interface with a SQLite (single node) and a networked backend.
5. **Signed configuration profiles** for Apple devices, so they don't
   show as unverified.
6. **DoH over HTTP/3,** tracked in
   [picatz/doh#73](https://github.com/picatz/doh/issues/73), waiting on
   Go's own HTTP/3.
