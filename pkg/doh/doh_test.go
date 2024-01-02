package doh_test

import (
	"context"
	"testing"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/picatz/doh/pkg/dj"
	"github.com/picatz/doh/pkg/doh"
)

func TestQuery(t *testing.T) {
	client := cleanhttp.DefaultClient()

	t.Run("google", func(t *testing.T) {
		req := &dj.Request{
			Name: "google.com",
			Type: "A",
		}

		resp, err := doh.SimpleQuery(context.Background(), client, doh.Google, req)
		if err != nil {
			t.Error(err)
		}

		if len(resp.Answer) == 0 {
			t.Error("got no answer for known domain")
		}
	})

	t.Run("cloudflare", func(t *testing.T) {
		req := &dj.Request{
			Name: "cloudflare.com",
			Type: "A",
		}

		resp, err := doh.SimpleQuery(context.Background(), client, doh.Cloudflare, req)
		if err != nil {
			t.Error(err)
		}

		if len(resp.Answer) == 0 {
			t.Error("got no answer for known domain")
		}
	})

	t.Run("quad9", func(t *testing.T) {
		req := &dj.Request{
			Name: "yahoo.com",
			Type: "A",
		}

		resp, err := doh.SimpleQuery(context.Background(), client, doh.Quad9, req)
		if err != nil {
			t.Error(err)
		}

		if len(resp.Answer) == 0 {
			t.Error("got no answer for known domain")
		}
	})

	t.Run("#9", func(t *testing.T) {
		servers := []string{
			"https://private.canadianshield.cira.ca/dns-query",
			"https://dns.adguard.com/dns-query",
			"https://doh.libredns.gr/dns-query",
			"https://doh.libredns.gr/ads",
			"https://dns.quad9.net/dns-query",
			"https://doh.opendns.com/dns-query",
			"https://doh.xfinity.com/dns-query",
			"https://doh.powerdns.org",
			// "https://doh.ffmuc.net/dns-query",
		}

		for _, server := range servers {
			t.Run(server, func(t *testing.T) {
				req := &dj.Request{
					Name: "google.com",
					Type: "A",
				}

				resp, err := doh.SimpleQuery(context.Background(), client, server, req)
				if err != nil {
					t.Error(err)
				}

				if len(resp.Answer) == 0 {
					t.Error("got no answer for known domain")
				}
			})
		}
	})
}
