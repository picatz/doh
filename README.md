# doh

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/picatz/doh/blob/master/LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/picatz/doh/pulls)

> 🍩  DNS over HTTPS command-line client and server

`doh` is a single binary for [DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc8484.html) (DoH):

- **`doh query`** looks up records from several DoH servers at once ([Cloudflare](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/), [Google](https://developers.google.com/speed/public-dns/docs/doh), and [Quad9](https://quad9.net/news/blog/doh-with-quad9-dns-servers/) by default, or your own), streaming the results as JSON.
- **`doh serve`** runs a DoH server that forwards queries to upstream resolvers over DoH, DNS-over-TLS, or plain DNS, with TLS from your own certificates or [Let's Encrypt](https://letsencrypt.org/).

It's also a Go library: [`pkg/doh`](https://pkg.go.dev/github.com/picatz/doh/pkg/doh) provides the client and server building blocks.

## Install

With [Go](https://go.dev/doc/install) 1.26 or later:

```console
$ go install github.com/picatz/doh@latest
```

## Querying

Query a domain's `A` records. Without `--servers`, Google, Cloudflare, and Quad9 are queried concurrently, and each response is printed as a line of JSON as it arrives:

```console
$ doh query example.com --servers https://dns.google/dns-query
{"server":"https://dns.google/dns-query","resp":{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"example.com.","type":1}],"Answer":[{"name":"example.com.","type":1,"TTL":300,"data":"172.66.147.243"},{"name":"example.com.","type":1,"TTL":300,"data":"104.20.23.154"}]}}
```

> [!TIP]
> Since `doh` outputs JSON lines, it pairs well with [`jq`](https://jqlang.org/):
>
> ```console
> $ doh query example.com | jq -c '{server, ips: [.resp.Answer[].data]}'
> {"server":"https://dns.google/dns-query","ips":["172.66.147.243","104.20.23.154"]}
> {"server":"https://cloudflare-dns.com/dns-query","ips":["104.20.23.154","172.66.147.243"]}
> ...
> ```

Query several domains at once, or other record types with `--type`:

```console
$ doh query example.com example.org --type AAAA
$ doh query google.com --type MX | jq -r '.resp.Answer[].data'
smtp.google.com.
```

Use any DoH server with `--servers`, and `--resolver-addr` to resolve the servers' own names through a specific DNS resolver (connecting directly, without `HTTP(S)_PROXY`):

```console
$ doh query example.com --servers https://dns.example/dns-query --resolver-addr 192.168.1.1:53
```

## Serving

`doh serve` runs a DoH server ([RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html)) that forwards queries to upstream resolvers, trying each in order until one answers. Upstreams can use DoH (`https://…`), DNS-over-TLS (`tls://host[:853]`), or plain DNS (`udp://host[:53]`, `tcp://host[:53]`, or just `host`), and default to Cloudflare and Google over DoH.

TLS is required unless you opt out with `--plaintext`, to run behind a reverse proxy or load balancer that terminates TLS:

```console
$ doh serve --plaintext --listen :8080 --upstream tls://dns.quad9.net
```

Certificates can come from files, which are reloaded automatically when they change:

```console
$ doh serve --tls-cert cert.pem --tls-key key.pem --upstream 192.168.1.1
```

Or be obtained and renewed automatically from Let's Encrypt (or another ACME CA with `--acme-directory`), answering TLS-ALPN-01 challenges on the TLS port:

```console
$ doh serve --acme-domain doh.example.com --acme-email admin@example.com
```

Then query it like any other DoH server:

```console
$ doh query example.com --servers https://doh.example.com/dns-query
```

### Configuration

Every flag can also be set with a `DOH_`-prefixed environment variable (`--tls-cert` is `DOH_TLS_CERT`, with commas separating lists), or in a JSON file passed with `--config`. Flags take precedence over the environment, which takes precedence over the file:

```json
{
  "listen": ":443",
  "upstreams": ["https://cloudflare-dns.com/dns-query", "tls://dns.quad9.net"],
  "timeout": "5s",
  "tls": {
    "acme": {
      "domains": ["doh.example.com"],
      "email": "admin@example.com",
      "http_listen": ":80"
    }
  },
  "log": { "level": "info", "format": "json" }
}
```

The server also exposes a `GET /healthz` liveness endpoint, logs every request at `--log-level debug`, and shuts down gracefully on interrupt.

## Go library

[`pkg/doh`](https://pkg.go.dev/github.com/picatz/doh/pkg/doh) works with any `*http.Client` and [`github.com/miekg/dns`](https://pkg.go.dev/github.com/miekg/dns) messages:

```go
resp, err := doh.Query(ctx, http.DefaultClient, doh.Cloudflare, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
```

And serving DoH is a handler away:

```go
mux := doh.NewServerMux(doh.Forwarder(http.DefaultClient, doh.Cloudflare, doh.Google))
log.Fatal(http.ListenAndServeTLS(":443", "cert.pem", "key.pem", mux))
```

## Reference

<details>
<summary><code>doh query --help</code></summary>

```console
$ doh query --help
Query DNS records from DoH servers using the given domains and record type.

Users can specify which servers to use for the query, or use the default servers from Google, Cloudflare, and Quad9.
They can also specify a timeout for the query, which defaults to 30 seconds if not specified. Each server is queried
in parallel, and each domain is queried in parallel. Results are streamed to STDOUT as JSON newline delimited objects,
which can be piped to other commands (e.g. jq) or redirected to a file.

Usage:
  doh query domains... [flags]

Flags:
  -h, --help                      help for query
  -k, --insecure-skip-verify      allow insecure server connections (e.g. self-signed TLS certificates)
      --resolver-addr string      address of a DNS resolver to use for resolving DoH server names (e.g. 8.8.8.8:53); connects directly, ignoring HTTP(S)_PROXY
      --resolver-network string   protocol to use for resolving DoH server names (e.g. udp, tcp) (default "udp")
      --retry-max int             maximum number of retries for each query (default 10)
      --servers strings           servers to query (default [https://dns.google/dns-query,https://cloudflare-dns.com/dns-query,https://dns.quad9.net:5053/dns-query])
      --timeout duration          timeout for query, 0s for no timeout (default 30s)
      --type string               dns record type to query for each domain, such as A, AAAA, MX, etc. (default "A")
```

</details>

<details>
<summary><code>doh serve --help</code></summary>

```console
$ doh serve --help
Serve DNS-over-HTTPS (RFC 8484), forwarding queries to upstream resolvers.

Upstreams are tried in order until one answers, and may use DNS-over-HTTPS
(https://), DNS-over-TLS (tls://host[:853]), or plain DNS (udp://host[:53],
tcp://host[:53], or just host).

TLS is required unless --plaintext is set, for running behind a reverse proxy
or load balancer that terminates TLS. Certificates come from files, reloaded
when they change, or are obtained automatically from Let's Encrypt (or another
ACME certificate authority) with --acme-domain.

Settings are read from, in increasing order of precedence: a JSON --config
file, DOH_* environment variables (e.g. DOH_TLS_CERT for --tls-cert, with
commas separating lists), and flags.

Examples:
  # Behind a TLS-terminating proxy, forwarding to Quad9 over DNS-over-TLS
  doh serve --plaintext --listen :8080 --upstream tls://dns.quad9.net

  # Public server with an automatic Let's Encrypt certificate
  doh serve --acme-domain doh.example.com --acme-email admin@example.com

  # With your own certificate, forwarding to a local resolver
  doh serve --tls-cert cert.pem --tls-key key.pem --upstream 192.168.1.1

Usage:
  doh serve [flags]

Flags:
      --acme-cache-dir string     directory for ACME accounts and certificates (default user cache dir)
      --acme-directory string     ACME directory URL (default Let's Encrypt)
      --acme-domain strings       domains to obtain ACME certificates for, enabling ACME
      --acme-email string         contact email for the ACME account
      --acme-http-listen string   address to answer ACME HTTP-01 challenges on, such as :80
      --config string             path to a JSON config file
  -h, --help                      help for serve
      --listen string             address to listen on (default ":443", or ":8080" with --plaintext)
      --log-format string         log format: text or json (default "text")
      --log-level string          log level: debug, info, warn, or error (default "info")
      --path string               URI path of the DoH endpoint (default "/dns-query")
      --plaintext                 serve unencrypted HTTP, behind a TLS-terminating proxy
      --timeout duration          maximum time to answer each query (default 5s)
      --tls-cert string           TLS certificate chain file (PEM)
      --tls-key string            TLS private key file (PEM)
      --upstream strings          upstream resolvers, tried in order (default [https://cloudflare-dns.com/dns-query,https://dns.google/dns-query])
```

</details>
