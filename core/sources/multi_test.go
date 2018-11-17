package sources

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	doh "github.com/picatz/doh/core"
)

func TestMulti(t *testing.T) {
	var (
		queryName = "yahoo.com"
		queryType = doh.IPv4Type
	)

	var (
		google     = &Google{}
		quad9      = &Quad9{}
		cloudflare = &Cloudflare{}
	)

	srcs := doh.Sources{google, quad9, cloudflare}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	wg := sync.WaitGroup{}

	wg.Add(len(srcs))

	for _, src := range srcs {
		go func(src doh.Source) {
			defer wg.Done()
			resp, err := src.Query(ctx, queryName, queryType)

			if err != nil {
				t.Error(err)
			}

			if len(resp.Answer) == 0 {
				t.Error("got no answer for known domain")
			}

			fmt.Println(src, resp, err, ctx.Err())
		}(src)
	}

	wg.Wait()
}
