package serve

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/serviceaccount"
)

// createAccount makes a service account and a key for it as c, returning
// a client that uses the key.
func createAccount(t *testing.T, c apiClient, body string) (serviceaccount.Account, apiClient) {
	t.Helper()
	resp, b := c.do(http.MethodPost, "/api/v1/service-accounts", body)
	var a serviceaccount.Account
	if err := json.Unmarshal(b, &a); resp.StatusCode != http.StatusCreated || err != nil {
		t.Fatalf("create service account = %d %s", resp.StatusCode, b)
	}
	resp, b = c.do(http.MethodPost, "/api/v1/service-accounts/"+a.ID+"/keys", "")
	var k api.NewKey
	if err := json.Unmarshal(b, &k); resp.StatusCode != http.StatusCreated || err != nil {
		t.Fatalf("add key = %d %s", resp.StatusCode, b)
	}
	return a, apiClient{t, c.base, k.Secret}
}

func TestServiceAccounts_TenantScoped(t *testing.T) {
	f := newTenantFixture(t)

	// The operator makes a reader for the smiths, and one of its own.
	smithBot, smithKey := createAccount(t, f.operator, `{"name":"Home Assistant","tenant":"smiths"}`)
	if smithBot.Tenant != "smiths" || smithBot.Role != serviceaccount.RoleReader || smithBot.CreatedBy != "admin token" {
		t.Fatalf("created %+v, want a reader for the smiths made by the admin token", smithBot)
	}
	opBot, _ := createAccount(t, f.operator, `{"name":"Backups","role":"admin"}`)

	// The smiths' key sees only the smiths' profiles, and can't change
	// them as a reader.
	resp, b := smithKey.do(http.MethodGet, "/api/v1/profiles", "")
	var profiles api.Profiles
	if err := json.Unmarshal(b, &profiles); resp.StatusCode != http.StatusOK || err != nil || len(profiles.Profiles) != 1 || profiles.Profiles[0].ID != "smith-home" {
		t.Fatalf("tenant key lists %d %s", resp.StatusCode, b)
	}
	if resp, _ := smithKey.do(http.MethodGet, "/api/v1/profiles/lab", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("tenant key reads the operator's profile: %d", resp.StatusCode)
	}
	if resp, _ := smithKey.do(http.MethodPatch, "/api/v1/profiles/smith-home", `{"safe_search":true}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("reader key changed a profile: %d", resp.StatusCode)
	}
	if resp, _ := smithKey.do(http.MethodGet, "/api/v1/policy", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("tenant key read the policy: %d", resp.StatusCode)
	}

	// The smiths' admin sees only their own service accounts; the
	// operator's look like they don't exist.
	var list api.ServiceAccounts
	if status := f.smith.do(http.MethodGet, "/api/v1/service-accounts", "", &list); status != http.StatusOK || len(list.ServiceAccounts) != 1 || list.ServiceAccounts[0].ID != smithBot.ID {
		t.Fatalf("tenant lists %d %+v", status, list)
	}
	for _, tt := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/service-accounts/" + opBot.ID},
		{http.MethodDelete, "/api/v1/service-accounts/" + opBot.ID},
		{http.MethodPost, "/api/v1/service-accounts/" + opBot.ID + "/keys"},
		{http.MethodPost, "/api/v1/service-accounts/" + opBot.ID + "/keys/" + "0123456789abcdef/rotate"},
		{http.MethodDelete, "/api/v1/service-accounts/" + opBot.ID + "/keys/" + "0123456789abcdef"},
	} {
		if status := f.smith.do(tt.method, tt.path, "", nil); status != http.StatusNotFound {
			t.Errorf("tenant %s %s = %d, want 404", tt.method, tt.path, status)
		}
	}
	if _, ok := f.s.accounts.Account(opBot.ID); !ok {
		t.Fatal("a tenant deleted the operator's service account")
	}

	// A tenant's admin makes service accounts only for its own tenant.
	var mine serviceaccount.Account
	if status := f.smith.do(http.MethodPost, "/api/v1/service-accounts", `{"name":"Script","role":"admin"}`, &mine); status != http.StatusCreated || mine.Tenant != "smiths" {
		t.Errorf("tenant create = %d %+v, want one in its own tenant", status, mine)
	}
	if status := f.smith.do(http.MethodPost, "/api/v1/service-accounts", `{"name":"x","tenant":"joneses"}`, nil); status != http.StatusForbidden {
		t.Errorf("tenant made a service account for another tenant: %d", status)
	}
	if resp, _ := f.operator.do(http.MethodPost, "/api/v1/service-accounts", `{"name":"x","tenant":"nobody"}`); resp.StatusCode != http.StatusNotFound {
		t.Errorf("service account for an unknown tenant: %d", resp.StatusCode)
	}
}

func TestServiceAccounts_CantManageIdentities(t *testing.T) {
	f := newTenantFixture(t)
	bot, key := createAccount(t, f.operator, `{"name":"Automation","role":"admin"}`)

	// Even an operator admin key can't mint sign-in links, more keys, a
	// longer life for itself, or remove people.
	for _, tt := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/signin-links", `{}`},
		{http.MethodGet, "/api/v1/people", ""},
		{http.MethodDelete, "/api/v1/people/someone", ""},
		{http.MethodGet, "/api/v1/service-accounts", ""},
		{http.MethodPost, "/api/v1/service-accounts", `{"name":"another","role":"admin"}`},
		{http.MethodPost, "/api/v1/service-accounts/" + bot.ID + "/keys", `{}`},
		{http.MethodPost, "/api/v1/service-accounts/" + bot.ID + "/keys/" + bot.ID + "/rotate", `{}`},
		{http.MethodDelete, "/api/v1/service-accounts/" + bot.ID, ""},
	} {
		if resp, b := key.do(tt.method, tt.path, tt.body); resp.StatusCode != http.StatusForbidden {
			t.Errorf("service account %s %s = %d %s, want 403", tt.method, tt.path, resp.StatusCode, b)
		}
	}

	// It can do its job, though.
	if resp, b := key.do(http.MethodPost, "/api/v1/profiles/lab/deny", `{"domain":"bot.example"}`); resp.StatusCode != http.StatusOK {
		t.Errorf("admin key couldn't change a profile: %d %s", resp.StatusCode, b)
	}
}

func TestServiceAccounts_RotateAndRevoke(t *testing.T) {
	f := newTenantFixture(t)
	bot, key := createAccount(t, f.operator, `{"name":"CI","role":"admin"}`)
	keyID := strings.Split(strings.TrimPrefix(key.token, serviceaccount.SecretPrefix), "_")[0]

	// Rotate with an hour's grace: both keys work until then.
	body := fmt.Sprintf(`{"previous_expires":%q}`, time.Now().Add(time.Hour).Format(time.RFC3339))
	resp, b := f.operator.do(http.MethodPost, "/api/v1/service-accounts/"+bot.ID+"/keys/"+keyID+"/rotate", body)
	var rotated api.NewKey
	if err := json.Unmarshal(b, &rotated); resp.StatusCode != http.StatusCreated || err != nil || rotated.Secret == key.token {
		t.Fatalf("rotate = %d %s", resp.StatusCode, b)
	}
	next := apiClient{t, key.base, rotated.Secret}
	for name, c := range map[string]apiClient{"old": key, "new": next} {
		if resp, _ := c.do(http.MethodGet, "/api/v1/status", ""); resp.StatusCode != http.StatusOK {
			t.Errorf("%s key during the grace period = %d", name, resp.StatusCode)
		}
	}

	// Grace beyond a week is refused.
	body = fmt.Sprintf(`{"previous_expires":%q}`, time.Now().Add(8*24*time.Hour).Format(time.RFC3339))
	if resp, _ := f.operator.do(http.MethodPost, "/api/v1/service-accounts/"+bot.ID+"/keys/"+rotated.Key.ID+"/rotate", body); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("rotating with 8 days' grace = %d, want 400", resp.StatusCode)
	}
	// So is a key lasting over a year.
	body = fmt.Sprintf(`{"expires":%q}`, time.Now().Add(400*24*time.Hour).Format(time.RFC3339))
	if resp, _ := f.operator.do(http.MethodPost, "/api/v1/service-accounts/"+bot.ID+"/keys", body); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a 400-day key = %d, want 400", resp.StatusCode)
	}

	// Revoking the old key stops it at once; the new one keeps working.
	if resp, _ := f.operator.do(http.MethodDelete, "/api/v1/service-accounts/"+bot.ID+"/keys/"+keyID, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke = %d", resp.StatusCode)
	}
	if resp, _ := key.do(http.MethodGet, "/api/v1/status", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked key = %d, want 401", resp.StatusCode)
	}
	if resp, _ := next.do(http.MethodGet, "/api/v1/status", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("remaining key = %d", resp.StatusCode)
	}

	// Deleting the account revokes every key.
	if resp, _ := f.operator.do(http.MethodDelete, "/api/v1/service-accounts/"+bot.ID, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	if resp, _ := next.do(http.MethodGet, "/api/v1/status", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("deleted account's key = %d, want 401", resp.StatusCode)
	}

	// Forged keys are refused, and say how to authenticate.
	forged := apiClient{t, key.base, rotated.Secret[:len(rotated.Secret)-2] + "AA"}
	if resp, _ := forged.do(http.MethodGet, "/api/v1/status", ""); resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("forged key = %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
}

func TestServiceAccounts_DeletedWithTheirTenant(t *testing.T) {
	f := newTenantFixture(t)
	_, key := createAccount(t, f.operator, `{"name":"Home Assistant","tenant":"smiths"}`)

	// The tenant's profile goes first, then the tenant.
	if resp, b := f.operator.do(http.MethodDelete, "/api/v1/profiles/smith-home", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete profile = %d %s", resp.StatusCode, b)
	}
	if resp, b := f.operator.do(http.MethodDelete, "/api/v1/tenants/smiths", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete tenant = %d %s", resp.StatusCode, b)
	}
	if resp, _ := key.do(http.MethodGet, "/api/v1/profiles", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("deleted tenant's key = %d, want 401", resp.StatusCode)
	}
	if n := len(f.s.accounts.Accounts()); n != 0 {
		t.Errorf("%d service accounts outlived their tenant", n)
	}
}

func TestServiceAccounts_RefusedWithoutTheirTenant(t *testing.T) {
	f := newTenantFixture(t)
	a, err := f.s.accounts.Create(serviceaccount.NewAccount{Name: "orphan", Tenant: "ghosts", Role: serviceaccount.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := f.s.accounts.AddKey(a.ID, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Its tenant was never in the policy, as if removed by hand.
	key := apiClient{t, f.operator.base, secret}
	if resp, _ := key.do(http.MethodGet, "/api/v1/profiles", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("key of a tenant that doesn't exist = %d, want 401", resp.StatusCode)
	}
}
