# doh
> 🍩  DNS over HTTPs command-line client

Using [`cloudflare`](https://developers.cloudflare.com/1.1.1.1/dns-over-https/), [`google`](https://developers.google.com/speed/public-dns/docs/dns-over-https), and [`quad9`](https://quad9.net/doh-quad9-dns-servers/) the `doh` command-line utility can concurrently lookup all three sources for one or more given domain(s).

> **Note** Since `doh` outputs everything as JSON, it pairs really well with tools like [`jq`](https://stedolan.github.io/jq/) to parse relevant parts of the output for your purposes.

# Install
To get started, you will need [`go`](https://golang.org/doc/install) installed and properly configured.
```shell
$ go get github.com/picatz/doh
```

# Update
As new updates come out, you can update `doh` using the `-u` flag with `go get`.
```shell
$ go get -u github.com/picatz/doh
``

# Help Menus
The `--help` command-line flag can show you the top-level help menu.
```shell
$ doh --help
```
```
Usage:
  doh [command]

Available Commands:
  help        Help about any command
  query       Query domains for DNS records in JSON

Flags:
  -h, --help   help for doh

Use "doh [command] --help" for more information about a command.
```

To get more information for the `query` command:
```shell
$ doh query --help
```
```
Query domains for DNS records in JSON

Usage:
  doh query [domains] [flags]

Flags:
  -h, --help              help for query
      --joined            join results into a JSON object
      --labels            show source of the dns record
      --limit int         limit the number of responses from backend sources (default 1)
      --lock int          number of concurrent workers (default 8)
      --no-limit          do not limit results
      --no-timeout        do not timeout
      --sources strings   sources to use for query (default [google,cloudflare,quad9])
      --timeout int       number of seconds until timeout (default 30)
      --type string       dns record type to query for ("A", "AAAA", "MX" ...) (default "A")
      --verbose           show errors and other available diagnostic information
```

# Example Usage
Let's say I'm curious about `google.com`'s IPv4 address and want to use `doh` to find out what it is.
```
$ doh query google.com 
```
```
{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"google.com.","type":1}],"Answer":[{"name":"google.com.","type":1,"TTL":100,"data":"172.217.8.206"}]}
```

If we want to filter the output to just the first IP address in the JSON response with `jq`:
```
$ doh query google.com | jq .Answer[0].data --raw-output
```
```
172.217.8.206
```

Now, perhaps `google.com` isn't the _only_ record we're also interested in, since we also want `bing.com`, which is where the _cool kids_ are at.
```
$ doh query bing.com apple.com --limit 2 | jq '(.Answer[0].name|rtrimstr(".")) + "\t" + .Answer[0].data' --raw-output
```
```
apple.com	172.217.8.206
bing.com	204.79.197.200
```