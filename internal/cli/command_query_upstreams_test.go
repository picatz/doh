package cli_test

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
	"github.com/picatz/doh/pkg/doh"
)

func TestCommand_Query_Upstreams(t *testing.T) {
	resetResolverFlags(t)

	answerA := func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg).SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.9"),
		})
		return resp
	}

	// A plain DNS server over UDP.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		_ = w.WriteMsg(answerA(req))
	})}
	ready := make(chan struct{})
	udp.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = udp.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = udp.Shutdown() })

	// A DoH server with a self-signed certificate.
	server := httptest.NewTLSServer(doh.NewServerMux(func(w http.ResponseWriter, r *http.Request, req *dns.Msg) (*dns.Msg, error) {
		return answerA(req), nil
	}))
	t.Cleanup(server.Close)

	udpServer := "udp://" + pc.LocalAddr().String()
	dohServer := server.URL + doh.DefaultPath

	// Set servers directly rather than with --servers: once parsed, pflag
	// appends to slice flags, which would leak into later tests.
	setResolverServers(t, udpServer, dohServer)
	output := testCommand(t, "query", "example.com", "-k")

	type line struct {
		Server string `json:"server"`
		TLS    *struct {
			Version     string `json:"version"`
			CipherSuite string `json:"cipher_suite"`
		} `json:"tls"`
		Resp struct {
			Answer []struct {
				Data string `json:"data"`
			} `json:"Answer"`
		} `json:"resp"`
	}

	got := map[string]line{}
	dec := json.NewDecoder(output)
	for dec.More() {
		var l line
		if err := dec.Decode(&l); err != nil {
			t.Fatal(err)
		}
		got[l.Server] = l
	}

	for _, server := range []string{udpServer, dohServer} {
		l, ok := got[server]
		if !ok {
			t.Fatalf("no result for %s in %v", server, got)
		}
		if len(l.Resp.Answer) != 1 || l.Resp.Answer[0].Data != "192.0.2.9" {
			t.Errorf("%s: got answers %+v, want 192.0.2.9", server, l.Resp.Answer)
		}
	}

	if l := got[udpServer]; l.TLS != nil {
		t.Errorf("plain DNS result has TLS details %+v", l.TLS)
	}
	if l := got[dohServer]; l.TLS == nil || l.TLS.Version != "TLS 1.3" || l.TLS.CipherSuite == "" {
		t.Errorf("DoH result has TLS details %+v, want TLS 1.3 with a cipher suite", l.TLS)
	}
}
