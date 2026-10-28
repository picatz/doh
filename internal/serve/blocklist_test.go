package serve

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/picatz/doh/pkg/doh"
)

// writeList writes a blocklist file and returns its path.
func writeList(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServer_Blocklist(t *testing.T) {
	list := writeList(t, "||ads.example.com^\n0.0.0.0 tracker.example.net\n")

	newServer := func(t *testing.T, config BlocklistConfig) *Server {
		t.Helper()

		config.Sources = append(config.Sources, "test="+list)
		config.CacheDir = t.TempDir()

		s, err := New(Config{Plaintext: true, Upstreams: []string{startResolver(t)}, Blocklist: config}, testLogger(t))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	edeOf := func(resp *dns.Msg) *dns.EDNS0_EDE {
		if opt := resp.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if ede, ok := o.(*dns.EDNS0_EDE); ok {
					return ede
				}
			}
		}
		return nil
	}

	t.Run("nxdomain over udp and doh", func(t *testing.T) {
		s := newServer(t, BlocklistConfig{})
		udpAddr, _ := startDNS(t, s)
		dohAddr := start(t, s)

		req := new(dns.Msg).SetQuestion("x.ads.example.com.", dns.TypeA)
		req.SetEdns0(dns.DefaultMsgSize, false)

		resp := exchange(t, "udp", udpAddr, req)
		if resp.Rcode != dns.RcodeNameError || len(resp.Answer) != 0 {
			t.Errorf("got %s with %d answers, want NXDOMAIN", dns.RcodeToString[resp.Rcode], len(resp.Answer))
		}

		ede := edeOf(resp)
		if ede == nil || ede.InfoCode != dns.ExtendedErrorCodeBlocked || !strings.Contains(ede.ExtraText, "test") {
			t.Errorf("got EDE %v, want Blocked by test", ede)
		}

		dohResp, err := doh.Query(t.Context(), &http.Client{Transport: &http.Transport{}}, "http://"+dohAddr+doh.DefaultPath, new(dns.Msg).SetQuestion("tracker.example.net.", dns.TypeA))
		if err != nil {
			t.Fatal(err)
		}
		if dohResp.Rcode != dns.RcodeNameError {
			t.Errorf("got %s over DoH, want NXDOMAIN", dns.RcodeToString[dohResp.Rcode])
		}

		// Without EDNS, no OPT record may be added.
		if resp := exchange(t, "udp", udpAddr, new(dns.Msg).SetQuestion("ads.example.com.", dns.TypeA)); resp.IsEdns0() != nil {
			t.Error("added an OPT record to a response for a client without EDNS")
		}

		if got := s.telemetry.blocked.Get("test"); got == nil || got.String() != "3" {
			t.Errorf("got %v blocked by test, want 3", got)
		}
	})

	t.Run("allowed and unlisted names resolve", func(t *testing.T) {
		s := newServer(t, BlocklistConfig{Allow: []string{"ok.ads.example.com"}})
		udpAddr, _ := startDNS(t, s)

		for _, name := range []string{"ok.ads.example.com.", "x.tracker.example.net.", "example.com."} {
			resp := exchange(t, "udp", udpAddr, new(dns.Msg).SetQuestion(name, dns.TypeA))
			if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
				t.Errorf("%s: got %s with %d answers, want the upstream's answer", name, dns.RcodeToString[resp.Rcode], len(resp.Answer))
			}
		}
	})

	t.Run("null response", func(t *testing.T) {
		s := newServer(t, BlocklistConfig{Response: BlockNull, Block: []string{"extra.example"}})
		udpAddr, _ := startDNS(t, s)

		tests := []struct {
			qtype uint16
			want  string
		}{
			{qtype: dns.TypeA, want: "0.0.0.0"},
			{qtype: dns.TypeAAAA, want: "::"},
			{qtype: dns.TypeMX},
		}

		for _, test := range tests {
			resp := exchange(t, "udp", udpAddr, new(dns.Msg).SetQuestion("ads.example.com.", test.qtype))

			if resp.Rcode != dns.RcodeSuccess {
				t.Errorf("%s: got %s, want NOERROR", dns.TypeToString[test.qtype], dns.RcodeToString[resp.Rcode])
				continue
			}

			switch {
			case test.want == "" && len(resp.Answer) != 0:
				t.Errorf("%s: got %v, want no records", dns.TypeToString[test.qtype], resp.Answer)
			case test.want != "" && (len(resp.Answer) != 1 || !strings.HasSuffix(resp.Answer[0].String(), test.want)):
				t.Errorf("%s: got %v, want %s", dns.TypeToString[test.qtype], resp.Answer, test.want)
			case test.want != "" && resp.Answer[0].Header().Ttl != blockedTTL:
				t.Errorf("%s: got TTL %d, want %d", dns.TypeToString[test.qtype], resp.Answer[0].Header().Ttl, blockedTTL)
			}
		}

		if resp := exchange(t, "udp", udpAddr, new(dns.Msg).SetQuestion("a.extra.example.", dns.TypeA)); len(resp.Answer) != 1 || !strings.HasSuffix(resp.Answer[0].String(), "0.0.0.0") {
			t.Errorf("got %v for a configured block domain, want 0.0.0.0", resp.Answer)
		}
	})

	t.Run("reload picks up list changes", func(t *testing.T) {
		s := newServer(t, BlocklistConfig{})

		if err := os.WriteFile(list, []byte("||new.example^\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.WriteFile(list, []byte("||ads.example.com^\n0.0.0.0 tracker.example.net\n"), 0o600) })

		if err := s.blocker.load(t.Context()); err != nil {
			t.Fatal(err)
		}

		if resp, _ := s.blocker.answer(new(dns.Msg).SetQuestion("new.example.", dns.TypeA)); resp == nil {
			t.Error("reloaded list doesn't block new.example")
		}
		if resp, _ := s.blocker.answer(new(dns.Msg).SetQuestion("ads.example.com.", dns.TypeA)); resp != nil {
			t.Error("reloaded list still blocks a removed rule")
		}
	})
}

func TestConfig_ValidateBlocklist(t *testing.T) {
	tests := []struct {
		name      string
		blocklist BlocklistConfig
		wantErr   string
	}{
		{name: "preset", blocklist: BlocklistConfig{Sources: []string{"default"}}},
		{name: "block domains only", blocklist: BlocklistConfig{Block: []string{"ads.example"}}},
		{name: "null response", blocklist: BlocklistConfig{Block: []string{"ads.example"}, Response: BlockNull}},
		{name: "unknown preset", blocklist: BlocklistConfig{Sources: []string{"oisd-tiny"}}, wantErr: "unknown preset"},
		{name: "bad response", blocklist: BlocklistConfig{Block: []string{"ads.example"}, Response: "refused"}, wantErr: "response"},
		{name: "refresh too often", blocklist: BlocklistConfig{Block: []string{"ads.example"}, Refresh: Duration(1)}, wantErr: "at least a minute"},
		{name: "allow alone", blocklist: BlocklistConfig{Allow: []string{"ok.example"}}, wantErr: "needs blocklist sources"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Config{Plaintext: true, Blocklist: test.blocklist}.Validate()

			switch {
			case test.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)):
				t.Fatalf("got error %v, want %q", err, test.wantErr)
			}
		})
	}
}
