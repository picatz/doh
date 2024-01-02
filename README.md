# doh

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/picatz/doh/blob/master/LICENSE)
[![go report](https://goreportcard.com/badge/github.com/picatz/doh)](https://goreportcard.com/report/github.com/picatz/doh)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/picatz/doh/pulls)

> 🍩  DNS over HTTPs command-line client

Using [`cloudflare`](https://developers.cloudflare.com/1.1.1.1/dns-over-https/), [`google`](https://developers.google.com/speed/public-dns/docs/dns-over-https), and [`quad9`](https://quad9.net/doh-quad9-dns-servers/) the `doh` command-line utility can concurrently lookup all three sources for one or more given domain(s). You can even specify your own custom source to use.

> [!NOTE]
> Since `doh` outputs everything as JSON, it pairs really well with tools like [`jq`](https://stedolan.github.io/jq/) to parse relevant parts of the output for your purposes.

# Install
To get started, you will need [`go`](https://golang.org/doc/install) installed and properly configured.
```shell
$ go install -v github.com/picatz/doh@latest
```

# Help Menus
The `--help` command-line flag can show you the top-level help menu.
```console
$ doh --help
Usage:
  doh [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  query       Query domains for DNS records in JSON

Flags:
  -h, --help   help for doh

Use "doh [command] --help" for more information about a command.
```

To get more information for the `query` command:
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
  -h, --help               help for query
      --servers strings    sources to use for query (default [https://dns.google.com/resolve,https://cloudflare-dns.com/dns-query,https://dns.quad9.net:5053/dns-query])
      --timeout duration   timeout for query, 0 for no timeout (default 30s)
      --type string        dns record type to query for ("A", "AAAA", "MX" ...) (default "A")
```

# Example Usage

Let's say we're curious about `google.com`'s IPv4 address. We can use `doh` to query three different sources (Google, Cloudflare, and Quad9) for the DNS `A` record type:

```console
$ doh query google.com
{"server":"https://dns.google.com/resolve","resp":{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"google.com.","type":1}],"Answer":[{"name":"google.com.","type":1,"TTL":283,"data":"172.217.2.46"}]}}
{"server":"https://cloudflare-dns.com/dns-query","resp":{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"google.com","type":1}],"Answer":[{"name":"google.com","type":1,"TTL":129,"data":"142.251.178.101"},{"name":"google.com","type":1,"TTL":129,"data":"142.251.178.138"},{"name":"google.com","type":1,"TTL":129,"data":"142.251.178.113"},{"name":"google.com","type":1,"TTL":129,"data":"142.251.178.102"},{"name":"google.com","type":1,"TTL":129,"data":"142.251.178.100"},{"name":"google.com","type":1,"TTL":129,"data":"142.251.178.139"}]}}
{"server":"https://dns.quad9.net:5053/dns-query","resp":{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"google.com.","type":1}],"Answer":[{"name":"google.com.","type":1,"TTL":34,"data":"142.250.191.142"}]}}
```

To get just all of the IPs from all of those sources, we could do the following:

```console
$ doh query google.com | jq -r '.resp.Answer[0].data'
172.217.2.46
142.251.178.113
142.250.191.142
```

We can also query multiple domains at once:

```console
$ doh query bing.com google.com | jq -r '(.resp.Answer[0].name|rtrimstr(".")) + "\t" + .resp.Answer[0].data' | sort -n
bing.com        13.107.21.200
bing.com        204.79.197.200
bing.com        204.79.197.200
google.com      142.250.191.142
google.com      142.251.178.102
google.com      172.217.0.174
```

To get `IPv6` records, we'll need to specify the `--type` flag, like so:
```
$ doh query google.com --type AAAA
...
```

To get `MX` records:
```
$ doh query google.com --type MX
...
```

To get `ANY` records (which is only implemented by Google at the moment):
```
$ doh query google.com --type ANY --servers=https://dns.google.com/resolve
...
```

> [!TIP]
>  To use a custom DNS over HTTPs source, specify the URL with the `--servers` flag.
