package cli

import (
	"os"
	"testing"

	"github.com/picatz/doh/internal/serve"
	"github.com/spf13/pflag"
)

// TestServeFlags_SMTPPassword checks that the SMTP password comes only
// from the environment, read once and removed, and never from a flag.
func TestServeFlags_SMTPPassword(t *testing.T) {
	t.Setenv(serve.SMTPPasswordEnv, "hunter2")
	fs := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags := defineServeFlags(fs)
	if err := fs.Parse([]string{"--smtp-url", "smtp://alerts@mail.example.com", "--smtp-from", "alerts@example.com"}); err != nil {
		t.Fatal(err)
	}
	config, err := flags.load()
	if err != nil {
		t.Fatal(err)
	}
	if config.Alerts.SMTP.Password.Reveal() != "hunter2" || config.Alerts.SMTP.URL != "smtp://alerts@mail.example.com" || config.Alerts.SMTP.From != "alerts@example.com" {
		t.Errorf("SMTP = %+v", config.Alerts.SMTP)
	}
	if _, ok := os.LookupEnv(serve.SMTPPasswordEnv); ok {
		t.Error("the password is still in the environment")
	}
	if fs.Lookup("smtp-password") != nil {
		t.Error("there's a flag for the password")
	}
}
