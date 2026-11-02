package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/client"
	"github.com/picatz/doh/internal/serviceaccount"
	"github.com/picatz/jose/pkg/dpop"
	"github.com/picatz/jose/pkg/dpop/dpophttp"
	"github.com/spf13/cobra"
)

// wantPrivateFile checks that path exists, readable only by its owner.
func wantPrivateFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("%s mode = %v, want 0600", path, fi.Mode().Perm())
	}
	return b
}

func TestServiceAccountCommands_DPoP(t *testing.T) {
	now := time.Now()
	responses := serviceAccountResponses(now)

	t.Run("key add --dpop writes the secret and its DPoP key", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ha.key")
		out, f, err := runClient(t, newServiceAccountCommand(), responses, "sa", "key", "add", "Home Assistant", "--dpop", "--secret-file", path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, testSecret) || !strings.Contains(out, path+".dpop") {
			t.Errorf("output:\n%s", out)
		}
		if got := strings.TrimSpace(string(wantPrivateFile(t, path))); got != testSecret {
			t.Errorf("secret file = %q", got)
		}
		signer, err := client.ParseDPoPKey(wantPrivateFile(t, path+".dpop"))
		if err != nil {
			t.Fatal(err)
		}
		var req api.KeyRequest
		if err := json.Unmarshal([]byte(f.bodies[len(f.bodies)-1]), &req); err != nil || req.JKT != signer.Thumbprint() {
			t.Errorf("key request = %s, want the jkt %s of the key written", f.bodies[len(f.bodies)-1], signer.Thumbprint())
		}

		// Neither file is ever overwritten, and nothing is made.
		dpopKey := wantPrivateFile(t, path+".dpop")
		if _, f, err := runClient(t, newServiceAccountCommand(), responses, "sa", "key", "add", "Home Assistant", "--dpop", "--secret-file", path); err == nil || len(f.requests) != 0 {
			t.Errorf("key add over existing files: %v after %d requests", err, len(f.requests))
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, f, err := runClient(t, newServiceAccountCommand(), responses, "sa", "key", "add", "Home Assistant", "--dpop", "--secret-file", path); err == nil || !strings.Contains(err.Error(), "already exists") || len(f.requests) != 0 {
			t.Errorf("key add over an existing DPoP key: %v after %d requests", err, len(f.requests))
		}
		if b, _ := os.ReadFile(path + ".dpop"); !bytes.Equal(b, dpopKey) {
			t.Error("the DPoP key was overwritten")
		}
		if _, err := os.Stat(path); err == nil {
			t.Error("a secret file was written anyway")
		}
	})

	t.Run("--dpop needs a secret file", func(t *testing.T) {
		for _, args := range [][]string{
			{"sa", "key", "add", "Home Assistant", "--dpop"},
			{"sa", "create", "x", "--dpop"},
			{"sa", "create", "x", "--dpop", "--no-key", "--secret-file", filepath.Join(t.TempDir(), "x")},
		} {
			if _, f, err := runClient(t, newServiceAccountCommand(), responses, args...); err == nil || len(f.requests) != 0 {
				t.Errorf("%v: %v after %d requests", args, err, len(f.requests))
			}
		}
	})

	t.Run("create --dpop binds the first key", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ha.key")
		_, f, err := runClient(t, newServiceAccountCommand(), responses, "sa", "create", "Home Assistant", "--dpop", "--secret-file", path, "--json")
		if err != nil {
			t.Fatal(err)
		}
		var req api.KeyRequest
		if err := json.Unmarshal([]byte(f.bodies[1]), &req); err != nil || !serviceaccount.ValidThumbprint(req.JKT) {
			t.Errorf("key request = %s", f.bodies[1])
		}
		wantPrivateFile(t, path+".dpop")
	})

	t.Run("rotating a bound key binds its replacement", func(t *testing.T) {
		bound := serviceAccountResponses(now)
		list := bound["GET /api/v1/service-accounts"].(api.ServiceAccounts)
		list.ServiceAccounts[1].Keys[1].JKT = strings.Repeat("A", 43)
		bound["GET /api/v1/service-accounts"] = list

		if out, _, err := runClient(t, newServiceAccountCommand(), bound, "sa", "list"); err != nil || !strings.Contains(out, "2222222222222222 (DPoP)") || strings.Contains(out, "1111111111111111 (DPoP)") {
			t.Errorf("list doesn't mark the bound key:\n%s", out)
		}

		if _, f, err := runClient(t, newServiceAccountCommand(), bound, "sa", "key", "rotate", "CI", "2222222222222222"); err == nil || !strings.Contains(err.Error(), "bound") || len(f.requests) != 1 {
			t.Errorf("rotate a bound key without a secret file: %v after %v", err, f.requests)
		}
		path := filepath.Join(t.TempDir(), "ci.key")
		_, f, err := runClient(t, newServiceAccountCommand(), bound, "sa", "key", "rotate", "CI", "2222222222222222", "--secret-file", path)
		var req api.RotateKeyRequest
		if err != nil || json.Unmarshal([]byte(f.bodies[len(f.bodies)-1]), &req) != nil || !serviceaccount.ValidThumbprint(req.JKT) {
			t.Errorf("rotate a bound key = %v, %s", err, f.bodies)
		}
		wantPrivateFile(t, path+".dpop")

		// --dpop=false makes the replacement a bearer key.
		_, f, err = runClient(t, newServiceAccountCommand(), bound, "sa", "key", "rotate", "CI", "2222222222222222", "--dpop=false")
		req = api.RotateKeyRequest{}
		if err != nil || json.Unmarshal([]byte(f.bodies[len(f.bodies)-1]), &req) != nil || req.JKT != "" {
			t.Errorf("rotate --dpop=false = %v, %s", err, f.bodies)
		}
	})
}

// dpopServer is an admin API that answers status only to requests
// with token, sent with the DPoP scheme and a proof by the key with
// thumbprint jkt.
func dpopServer(t *testing.T, token, jkt string) *httptest.Server {
	t.Helper()
	v := &dpop.Verifier{Replay: dpop.NewMemoryReplayCache(10, nil)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := dpophttp.AccessTokenFromRequest(r)
		proof, perr := dpophttp.FromRequest(r)
		if err != nil || perr != nil || got != token {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(api.Error{Error: "want a DPoP-bound token"})
			return
		}
		if _, err := v.Verify(r.Context(), proof, dpop.Request{Method: r.Method, URI: "http://" + r.Host + r.URL.Path, AccessToken: token, Thumbprint: jkt}); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(api.Error{Error: err.Error()})
			return
		}
		json.NewEncoder(w).Encode(api.Status{Version: "v9"})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runStatus(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := &cobra.Command{Use: "doh", SilenceErrors: true}
	root.AddCommand(newStatusCommand())
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(io.Discard)
	root.SetArgs(append([]string{"status"}, args...))
	err := root.Execute()
	return out.String(), err
}

func TestClientFlags_DPoPKey(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "ci.key")
	if err := os.WriteFile(tokenFile, []byte(testSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, _ := client.GenerateDPoPKey()
	signer, _ := client.NewDPoPSigner(key)
	b, _ := client.MarshalDPoPKey(key)
	srv := dpopServer(t, testSecret, signer.Thumbprint())

	// Without the key, the bound token alone is refused.
	if _, err := runStatus(t, "--addr", srv.URL, "--token-file", tokenFile); err == nil {
		t.Fatal("status without the DPoP key succeeded")
	}

	// --dpop-key, or DOH_DPOP_KEY_FILE, names it.
	keyFile := filepath.Join(dir, "elsewhere.pem")
	if err := os.WriteFile(keyFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runStatus(t, "--addr", srv.URL, "--token", testSecret, "--dpop-key", keyFile); err != nil || !strings.Contains(out, "v9") {
		t.Errorf("status --dpop-key = %q, %v", out, err)
	}
	t.Setenv(envDPoPKeyFile, keyFile)
	if out, err := runStatus(t, "--addr", srv.URL, "--token", testSecret); err != nil || !strings.Contains(out, "v9") {
		t.Errorf("status with %s = %q, %v", envDPoPKeyFile, out, err)
	}
	t.Setenv(envDPoPKeyFile, "")

	// The token file's .dpop sibling is found on its own.
	if err := os.WriteFile(tokenFile+".dpop", b, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runStatus(t, "--addr", srv.URL, "--token-file", tokenFile); err != nil || !strings.Contains(out, "v9") {
		t.Errorf("status with a sibling key = %q, %v", out, err)
	}

	// A key that isn't one is an error, not a silent bearer request.
	if _, err := runStatus(t, "--addr", srv.URL, "--token", testSecret, "--dpop-key", tokenFile); err == nil || !strings.Contains(err.Error(), "DPoP key") {
		t.Errorf("status with a bad key: %v", err)
	}
}

func TestTokenExchangeCommand_DPoP(t *testing.T) {
	var proofs, uris []string
	handler := func(w http.ResponseWriter, r *http.Request) {
		proofs, uris = append(proofs, r.Header.Get("DPoP")), append(uris, "http://"+r.Host+r.URL.Path)
		if r.Header.Get("DPoP") == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(api.OAuthError{Error: "invalid_dpop_proof"})
			return
		}
		json.NewEncoder(w).Encode(api.TokenResponse{AccessToken: "doh_at_abc", TokenType: "DPoP", IssuedTokenType: api.TokenTypeAccessToken, ExpiresIn: 900})
	}
	dir := t.TempDir()
	id := filepath.Join(dir, "id.jwt")
	if err := os.WriteFile(id, []byte("eyJ.id.token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(dir, "dpop.pem")
	out, err := runTokenExchange(t, handler, "", "--account", "ciiiiiiiiiiiiiii", "--subject-token-file", id, "--new-dpop-key", keyFile)
	if err != nil || out != "doh_at_abc\n" {
		t.Fatalf("exchange --new-dpop-key = %q, %v", out, err)
	}
	signer, err := client.ParseDPoPKey(wantPrivateFile(t, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	// The proof is for the exchange, by the key written.
	if _, err := (&dpop.Verifier{}).Verify(t.Context(), proofs[0], dpop.Request{Method: http.MethodPost, URI: uris[0], Thumbprint: signer.Thumbprint()}); err != nil {
		t.Errorf("exchange proof: %v", err)
	}

	// An existing key is never overwritten, and is used with --dpop-key.
	before, _ := os.ReadFile(keyFile)
	if _, err := runTokenExchange(t, handler, "", "--account", "ciiiiiiiiiiiiiii", "--subject-token-file", id, "--new-dpop-key", keyFile); err == nil {
		t.Error("--new-dpop-key over an existing file succeeded")
	}
	if after, _ := os.ReadFile(keyFile); !bytes.Equal(before, after) {
		t.Error("--new-dpop-key overwrote a key")
	}
	if _, err := runTokenExchange(t, handler, "", "--account", "ciiiiiiiiiiiiiii", "--subject-token-file", id, "--dpop-key", keyFile); err != nil {
		t.Errorf("exchange --dpop-key: %v", err)
	}
	if _, err := runTokenExchange(t, handler, "", "--account", "ciiiiiiiiiiiiiii", "--subject-token-file", id, "--dpop-key", keyFile, "--new-dpop-key", filepath.Join(dir, "x")); err == nil {
		t.Error("--dpop-key with --new-dpop-key succeeded")
	}

	// A refused exchange leaves no new key behind.
	refusing := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(api.OAuthError{Error: "invalid_grant"})
	}
	unused := filepath.Join(dir, "unused.pem")
	if _, err := runTokenExchange(t, refusing, "", "--account", "ciiiiiiiiiiiiiii", "--subject-token-file", id, "--new-dpop-key", unused); err == nil {
		t.Fatal("refused exchange succeeded")
	}
	if _, err := os.Stat(unused); err == nil {
		t.Error("a refused exchange left its new DPoP key behind")
	}
}
