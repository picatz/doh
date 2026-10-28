package cli_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/cli"
	"github.com/picatz/doh/pkg/dj"
	"github.com/picatz/doh/pkg/doh"
)

func resetResolverFlags(t *testing.T) {
	t.Helper()
	flags := cli.CommandQuery.Flags()
	for _, name := range []string{"resolver-addr", "resolver-network", "insecure-skip-verify", "retry-max", "timeout"} {
		flag := flags.Lookup(name)
		value, changed := flag.Value.String(), flag.Changed
		t.Cleanup(func() {
			if err := flag.Value.Set(value); err != nil {
				t.Error(err)
			}
			flag.Changed = changed
		})
	}
	servers, err := flags.GetStringSlice("servers")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { setResolverServers(t, servers...) })
}

func setResolverServers(t *testing.T, servers ...string) {
	t.Helper()
	value := cli.CommandQuery.Flags().Lookup("servers").Value.(interface{ Replace([]string) error })
	if err := value.Replace(servers); err != nil {
		t.Error(err)
	}
}

func TestCommand_Query_CustomResolver(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		for _, secure := range []bool{false, true} {
			name := network + "/http"
			if secure {
				name = network + "/https"
			}
			retry := network == "tcp" && secure
			if retry {
				name += "/retry"
			}
			t.Run(name, func(t *testing.T) {
				resetResolverFlags(t)
				defer func() {
					if value := recover(); value != nil {
						t.Errorf("custom resolver panicked: %v", value)
					}
				}()

				var queries atomic.Int32
				resolver := &dns.Server{Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
					queries.Add(1)
					resp := new(dns.Msg)
					resp.SetReply(req)
					for _, question := range req.Question {
						if question.Name != "doh.test." {
							t.Errorf("unexpected resolver question: %s", question.Name)
						}
						if question.Qtype == dns.TypeA {
							resp.Answer = append(resp.Answer, &dns.A{
								Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
								A:   net.ParseIP("127.0.0.1"),
							})
						}
					}
					if err := w.WriteMsg(resp); err != nil {
						t.Error(err)
					}
				})}
				var resolverAddr string
				if network == "udp" {
					conn, err := net.ListenPacket(network, "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					resolver.PacketConn = conn
					resolverAddr = conn.LocalAddr().String()
				} else {
					listener, err := net.Listen(network, "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					resolver.Listener = listener
					resolverAddr = listener.Addr().String()
				}
				ready := make(chan struct{})
				resolver.NotifyStartedFunc = func() { close(ready) }
				done := make(chan error, 1)
				go func() { done <- resolver.ActivateAndServe() }()
				<-ready
				t.Cleanup(func() {
					if err := resolver.Shutdown(); err != nil {
						t.Error(err)
					}
					if err := <-done; err != nil {
						t.Error(err)
					}
				})

				mux := doh.NewServerMux(func(w http.ResponseWriter, r *http.Request, req *dns.Msg) (*dns.Msg, error) {
					if req.Question[0].Name != "example.com." {
						t.Errorf("unexpected DoH question: %s", req.Question[0].Name)
					}
					resp := new(dns.Msg)
					resp.SetReply(req)
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("198.51.100.7"),
					})
					return resp, nil
				})
				var requests atomic.Int32
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if requests.Add(1) == 1 && retry {
						http.Error(w, "retry", http.StatusServiceUnavailable)
						return
					}
					mux.ServeHTTP(w, r)
				})
				var server *httptest.Server
				if secure {
					server = httptest.NewTLSServer(handler)
				} else {
					server = httptest.NewServer(handler)
				}
				t.Cleanup(server.Close)
				serverURL, err := url.Parse(server.URL + "/dns-query")
				if err != nil {
					t.Fatal(err)
				}
				serverURL.Host = net.JoinHostPort("doh.test", serverURL.Port())
				setResolverServers(t, serverURL.String())
				retryMax := 0
				if retry {
					retryMax = 1
				}

				output := testCommand(t, "query", "example.com",
					"--resolver-addr", resolverAddr, "--resolver-network", network,
					"--retry-max", strconv.Itoa(retryMax), "--timeout", "5s", "--insecure-skip-verify="+strconv.FormatBool(secure))
				var result struct {
					Server string      `json:"server"`
					Resp   dj.Response `json:"resp"`
				}
				if err := json.NewDecoder(output).Decode(&result); err != nil {
					t.Fatal(err)
				}
				if result.Server != serverURL.String() || len(result.Resp.Answer) != 1 || result.Resp.Answer[0].Data != "198.51.100.7" {
					t.Errorf("unexpected result: %+v", result)
				}
				if queries.Load() == 0 {
					t.Error("custom resolver was not queried")
				}
				if got, want := requests.Load(), int32(retryMax+1); got != want {
					t.Errorf("got %d requests, want %d", got, want)
				}
			})
		}
	}
}

func TestCommand_Query_CustomResolverError(t *testing.T) {
	resetResolverFlags(t)
	defer func() {
		if value := recover(); value != nil {
			t.Errorf("custom resolver panicked: %v", value)
		}
	}()
	setResolverServers(t, "http://doh.test/dns-query")
	cli.CommandRoot.SetArgs([]string{"query", "example.com",
		"--resolver-addr", "127.0.0.1:0", "--resolver-network", "tcp", "--retry-max", "0", "--timeout", "1s"})
	cli.CommandRoot.SetOut(new(bytes.Buffer))
	cli.CommandRoot.SetErr(io.Discard)
	t.Cleanup(func() { cli.CommandRoot.SetErr(nil) })
	if err := cli.CommandRoot.Execute(); err == nil || !strings.Contains(err.Error(), "error dialing with custom resolver") {
		t.Errorf("expected custom resolver error, got %v", err)
	}
}

// TestCommand_Query_CustomResolverBypassesProxy runs the custom resolver
// tests in a subprocess with an unreachable proxy configured, since
// net/http reads proxy environment variables only once per process.
func TestCommand_Query_CustomResolverBypassesProxy(t *testing.T) {
	if os.Getenv("DOH_TEST_PROXY_SUBPROCESS") != "" {
		t.Skip("already running in the proxy subprocess")
	}

	// Reserve a port, then close it so the proxy refuses connections.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyURL := "http://" + listener.Addr().String()
	listener.Close()

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestCommand_Query_CustomResolver$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		"DOH_TEST_PROXY_SUBPROCESS=1",
		"HTTP_PROXY="+proxyURL, "HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL, "https_proxy="+proxyURL,
		"NO_PROXY=", "no_proxy=",
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("custom resolver tests failed with a proxy configured: %v\n%s", err, output)
	}
}
