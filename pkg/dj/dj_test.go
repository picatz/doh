package dj_test

import (
	"context"
	"testing"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/picatz/doh/pkg/dj"
)

func TestQuery(t *testing.T) {
	client := cleanhttp.DefaultClient()

	t.Run("google", func(t *testing.T) {
		req := &dj.Request{
			Name: "google.com",
			Type: dj.RecordA,
		}

		resp, err := dj.Query(context.Background(), client, dj.Google, req)
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
			Type: dj.RecordA,
		}

		resp, err := dj.Query(context.Background(), client, dj.Cloudflare, req)
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
			Type: dj.RecordA,
		}

		resp, err := dj.Query(context.Background(), client, dj.Quad9, req)
		if err != nil {
			t.Error(err)
		}

		if len(resp.Answer) == 0 {
			t.Error("got no answer for known domain")
		}
	})
}
