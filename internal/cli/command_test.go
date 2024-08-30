package cli_test

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/cli"
	"github.com/picatz/doh/pkg/doh"
)

func testCommand(t *testing.T, args ...string) io.Reader {
	t.Helper()

	cli.CommandRoot.SetArgs(args)

	output := bytes.NewBuffer(nil)

	cli.CommandRoot.SetOut(output)

	err := cli.CommandRoot.Execute()
	if err != nil {
		t.Fatal(err)
	}

	return output
}

func TestCommand(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		check func(t *testing.T, output io.Reader)
	}{
		{
			name: "help",
			args: []string{"--help"},
			check: func(t *testing.T, output io.Reader) {
				b, err := io.ReadAll(output)
				if err != nil {
					t.Fatal(err)
				}

				if len(b) == 0 {
					t.Error("got no help output")
				}
			},
		},
		{
			name: "query google.com",
			args: []string{"query", "google.com"},
			check: func(t *testing.T, output io.Reader) {
				b, err := io.ReadAll(output)
				if err != nil {
					t.Fatal(err)
				}

				if len(b) == 0 {
					t.Fatal("got no output for known domain")
				}

				t.Log(string(b))
			},
		},
		{
			name: "query cloudflare.com",
			args: []string{"query", "cloudflare.com"},
			check: func(t *testing.T, output io.Reader) {
				b, err := io.ReadAll(output)
				if err != nil {
					t.Fatal(err)
				}

				if len(b) == 0 {
					t.Fatal("got no output for known domain")
				}

				t.Log(string(b))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := testCommand(t, test.args...)

			test.check(t, output)
		})
	}
}

func TestCommand_Query_InsecureSkipVerify(t *testing.T) {
	mux := doh.NewServerMux(func(w http.ResponseWriter, httpReq *http.Request, dnsReq *dns.Msg) (*dns.Msg, error) {
		dnsResp := new(dns.Msg)
		dnsResp.SetReply(dnsReq)
		dnsResp.Answer = append(dnsResp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   dnsReq.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("8.8.8.8"),
		})

		return dnsResp, nil
	})

	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	dohServerURL := server.URL + "/dns-query"

	output := testCommand(t, "query", "google.com", "--insecure-skip-verify", "--servers", dohServerURL)

	b, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}

	if len(b) == 0 {
		t.Fatal("got no output for known domain")
	}

	t.Log(string(b))
}
