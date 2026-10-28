package serve

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/blocklist"
)

// blockedTTL is the TTL of synthesized answers for blocked names, short so
// that unblocking a name takes effect quickly.
const blockedTTL = 60

// blocker answers queries for blocked names, using lists it refreshes in
// the background.
type blocker struct {
	config  BlocklistConfig
	sources []blocklist.Source
	loader  *blocklist.Loader
	logger  *slog.Logger

	list atomic.Pointer[blocklist.List]
}

// newBlocker loads the configured blocklists.
func newBlocker(ctx context.Context, config BlocklistConfig, logger *slog.Logger) (*blocker, error) {
	b := &blocker{
		config: config,
		loader: &blocklist.Loader{
			Client:   &http.Client{Timeout: time.Minute},
			CacheDir: config.CacheDir,
			Logger:   logger,
		},
		logger: logger,
	}

	for _, s := range config.Sources {
		src, err := blocklist.ParseSource(s)
		if err != nil {
			return nil, err
		}
		b.sources = append(b.sources, src)
	}

	if err := b.load(ctx); err != nil {
		return nil, err
	}

	return b, nil
}

// load loads the lists, replacing the current ones.
func (b *blocker) load(ctx context.Context) error {
	list, err := b.loader.Load(ctx, b.sources, b.config.Block, b.config.Allow)
	if err != nil {
		return err
	}

	b.list.Store(list)
	b.logger.InfoContext(ctx, "blocklist loaded", slog.Int("rules", list.Len()), slog.Int("sources", len(b.sources)))

	return nil
}

// refresh reloads the lists every interval until ctx is done, keeping the
// current lists if a reload fails.
func (b *blocker) refresh(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := b.load(ctx); err != nil && ctx.Err() == nil {
				b.logger.WarnContext(ctx, "blocklist refresh failed, keeping current lists", slog.Any("error", err))
			}
		}
	}
}

// answer returns a synthesized response if query asks for a blocked name.
func (b *blocker) answer(query *dns.Msg) (*dns.Msg, blocklist.Verdict) {
	v := b.list.Load().Lookup(query.Question[0].Name)
	if !v.Blocked {
		return nil, v
	}

	resp := new(dns.Msg).SetReply(query)
	resp.RecursionAvailable = true

	q := query.Question[0]
	switch {
	case b.config.Response == BlockNull && q.Qtype == dns.TypeA:
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: blockedTTL},
			A:   net.IPv4zero,
		})
	case b.config.Response == BlockNull && q.Qtype == dns.TypeAAAA:
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: blockedTTL},
			AAAA: net.IPv6zero,
		})
	case b.config.Response == BlockNull:
		// Other types get an empty answer (NODATA).
	default:
		resp.Rcode = dns.RcodeNameError
	}

	// Tell EDNS clients why, with an Extended DNS Error (RFC 8914,
	// Section 4.16), so a block isn't mistaken for a failure.
	if opt := query.IsEdns0(); opt != nil {
		resp.SetEdns0(dns.DefaultMsgSize, opt.Do())
		resp.IsEdns0().Option = append(resp.IsEdns0().Option, &dns.EDNS0_EDE{
			InfoCode:  dns.ExtendedErrorCodeBlocked,
			ExtraText: "blocked by " + v.Source,
		})
	}

	return resp, v
}
