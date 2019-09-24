package sources

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestCustomQuery(t *testing.T) {
	var (
		queryName = "yahoo.com"
		queryType = "A"

		sourceName = "google-but-custom-tho"
		baseURL    = "https://dns.google.com/resolve"
	)

	src := NewCustomSource(sourceName, baseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := src.Query(ctx, queryName, queryType)

	if err != nil {
		t.Error(err)
	}

	if len(resp.Answer) == 0 {
		t.Error("got no answer for known domain")
	}

	fmt.Println(src, resp, err, ctx.Err())
}
