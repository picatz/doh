package serve

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/picatz/doh/internal/alerts"
	"github.com/picatz/doh/internal/api"
)

// subscriptionJSON is a browser's PushSubscription at endpoint, with new
// keys.
func subscriptionJSON(t *testing.T, endpoint string) string {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	_, _ = rand.Read(auth)
	b, _ := json.Marshal(map[string]any{"endpoint": endpoint, "expirationTime": nil, "keys": map[string]string{
		"p256dh": base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()),
		"auth":   base64.RawURLEncoding.EncodeToString(auth),
	}})
	return string(b)
}

func TestAlertsAPI_PushAndEmail(t *testing.T) {
	f := newTenantFixture(t)

	// The push key is the same for every caller, kept privately.
	var key api.PushKey
	if status := f.smith.do(http.MethodGet, "/api/v1/alerts/push-key", "", &key); status != http.StatusOK {
		t.Fatalf("push key = %d", status)
	}
	if raw, err := base64.RawURLEncoding.DecodeString(key.PublicKey); err != nil || len(raw) != 65 || raw[0] != 4 {
		t.Fatalf("push key = %q", key.PublicKey)
	}
	resp, b := f.operator.do(http.MethodGet, "/api/v1/alerts/push-key", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), key.PublicKey) {
		t.Errorf("operator's push key = %d %s", resp.StatusCode, b)
	}
	if info, err := os.Stat(filepath.Join(f.s.config.DataDir, PushKeyFile)); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("push key file: %v, %v", info, err)
	}
	reader := apiClient{t, f.operator.base, token(t, f.s.config.DataDir, ReaderTokenFile)}
	if resp, _ := reader.do(http.MethodGet, "/api/v1/alerts/push-key", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("reader's push key = %d, want 403", resp.StatusCode)
	}

	// A browser subscribes; what would let anyone else push to it isn't
	// shown.
	endpoint := "https://fcm.googleapis.com/fcm/send/this-browsers-token"
	var added api.NewAlertDestination
	if status := f.smith.do(http.MethodPost, "/api/v1/alerts/destinations", `{"type":"push","name":"Alex's phone","subscription":`+subscriptionJSON(t, endpoint)+`}`, &added); status != http.StatusCreated {
		t.Fatalf("add push = %d", status)
	}
	d := added.Destination
	if d.Type != alerts.Push || d.State != alerts.Active || d.URL != "https://fcm.googleapis.com/…" || d.Subscription != alerts.SubscriptionID(endpoint) || added.Secret != "" {
		t.Fatalf("added %+v", added)
	}
	resp, b = f.operator.do(http.MethodGet, "/api/v1/alerts?tenant=smiths", "")
	if resp.StatusCode != http.StatusOK || strings.Contains(string(b), "this-browsers-token") || strings.Contains(string(b), `"auth"`) {
		t.Errorf("the view shows the subscription: %s", b)
	}

	// Only browser push services, never anything else.
	for _, ep := range []string{"https://push.evil.example/x", "https://10.0.0.1/x", "https://127.0.0.1/x", "http://fcm.googleapis.com/x", "https://fcm.googleapis.com:8443/x"} {
		if status := f.smith.do(http.MethodPost, "/api/v1/alerts/destinations", `{"type":"push","subscription":`+subscriptionJSON(t, ep)+`}`, nil); status != http.StatusBadRequest {
			t.Errorf("push to %s = %d, want 400", ep, status)
		}
	}
	for _, body := range []string{`{"type":"push"}`, `{"type":"push","subscription":{"endpoint":"` + endpoint + `"}}`, `{"type":"push","subscription":{"endpoint":"` + endpoint + `","keys":{"p256dh":"AAAA","auth":"AAAA"}}}`} {
		if status := f.smith.do(http.MethodPost, "/api/v1/alerts/destinations", body, nil); status != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", body, status)
		}
	}

	// Without a mail server, email isn't offered.
	var view api.Alerts
	if status := f.smith.do(http.MethodGet, "/api/v1/alerts", "", &view); status != http.StatusOK || slices.Contains(view.AvailableTypes, alerts.Email) || !slices.Contains(view.AvailableTypes, alerts.Push) {
		t.Errorf("available types = %v", view.AvailableTypes)
	}
	if status := f.smith.do(http.MethodPost, "/api/v1/alerts/destinations", `{"type":"email","address":"alex@example.com"}`, nil); status != http.StatusConflict {
		t.Errorf("add email without a mail server = %d, want 409", status)
	}
	if status := f.smith.do(http.MethodPost, "/api/v1/alerts/confirm", `{"code":"ABCDE-FGHJK"}`, nil); status != http.StatusNotFound {
		t.Errorf("confirm a code never sent = %d, want 404", status)
	}
	if resp, _ := reader.do(http.MethodPost, "/api/v1/alerts/confirm", `{"code":"ABCDE-FGHJK"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("reader confirming = %d, want 403", resp.StatusCode)
	}
}

func TestConfig_ValidateSMTP(t *testing.T) {
	const password = "hunter2-correct-horse"
	file := filepath.Join(t.TempDir(), "smtp.password")
	_ = os.WriteFile(file, []byte(password+"\n"), 0o600)
	smtp := func(c SMTPConfig) Config { return Config{Plaintext: true, Alerts: AlertsConfig{SMTP: c}} }
	for desc, tt := range map[string]struct {
		config Config
		ok     bool
	}{
		"none":                    {smtp(SMTPConfig{}), true},
		"a file":                  {smtp(SMTPConfig{URL: "smtp://alerts@mail.example.com", PasswordFile: file, From: "doh <alerts@example.com>"}), true},
		"the environment":         {smtp(SMTPConfig{URL: "smtps://alerts@mail.example.com", Password: password, From: "alerts@example.com"}), true},
		"no user, no password":    {smtp(SMTPConfig{URL: "smtp://127.0.0.1:25", From: "alerts@example.com"}), true},
		"both":                    {smtp(SMTPConfig{URL: "smtp://alerts@mail.example.com", PasswordFile: file, Password: password, From: "alerts@example.com"}), false},
		"a password in the URL":   {smtp(SMTPConfig{URL: "smtp://alerts:" + password + "@mail.example.com", From: "alerts@example.com"}), false},
		"no sender":               {smtp(SMTPConfig{URL: "smtp://mail.example.com"}), false},
		"a user without password": {smtp(SMTPConfig{URL: "smtp://alerts@mail.example.com", From: "alerts@example.com"}), false},
		"a sender without a URL":  {smtp(SMTPConfig{From: "alerts@example.com"}), false},
		"a password without URL":  {smtp(SMTPConfig{Password: password}), false},
		"http":                    {smtp(SMTPConfig{URL: "http://mail.example.com", From: "alerts@example.com"}), false},
	} {
		err := tt.config.Validate()
		if (err == nil) != tt.ok {
			t.Errorf("%s: Validate = %v, want ok %v", desc, err, tt.ok)
		}
		if err != nil && strings.Contains(err.Error(), password) {
			t.Errorf("%s: the error shows the password: %v", desc, err)
		}
	}

	// The password is read from its file, and never written to JSON.
	c := smtp(SMTPConfig{URL: "smtp://alerts@mail.example.com", PasswordFile: file, From: "alerts@example.com", Password: "from-env"})
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "from-env") {
		t.Errorf("the config's JSON has the password: %s", b)
	}
	c.Alerts.SMTP.Password = ""
	mc, err := c.Alerts.SMTP.mailConfig()
	if err != nil || mc.Password.Reveal() != password {
		t.Errorf("mailConfig = %v", err)
	}
}

// TestAlertPages checks the pages alert emails link to, which anyone may
// open: opening one changes nothing, they're strict, and wrong codes are
// limited.
func TestAlertPages(t *testing.T) {
	f := newTenantFixture(t)
	base := f.operator.base

	for _, path := range []string{alerts.ConfirmPath + "ABCDEFGHJK", alerts.UnsubscribePath + "token"} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		csp := resp.Header.Get("Content-Security-Policy")
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), `<form method="post">`) ||
			!strings.Contains(csp, "form-action 'self'") || strings.Contains(csp, "script-src") || !strings.Contains(csp, "require-trusted-types-for") ||
			resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Frame-Options") != "DENY" {
			t.Errorf("GET %s = %d %q %v\n%s", path, resp.StatusCode, csp, resp.Header, b)
		}
	}

	post := func(path string) int {
		resp, err := http.Post(base+path, "application/x-www-form-urlencoded", strings.NewReader("List-Unsubscribe=One-Click"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if status := post(alerts.ConfirmPath + "ABCDEFGHJK"); status != http.StatusNotFound {
		t.Errorf("POST a forged code = %d, want 404", status)
	}
	if status := post(alerts.UnsubscribePath + "forged"); status != http.StatusNotFound {
		t.Errorf("POST a forged unsubscribe token = %d, want 404", status)
	}
	for range 20 {
		post(alerts.ConfirmPath + "ABCDEFGHJK")
	}
	if status := post(alerts.ConfirmPath + "ABCDEFGHJK"); status != http.StatusTooManyRequests {
		t.Errorf("after many wrong codes = %d, want 429", status)
	}
}
