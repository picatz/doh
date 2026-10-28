package cli

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/picatz/doh/internal/serve"
	"github.com/spf13/pflag"
)

func TestLoadServeConfig(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "config.json")
	err := os.WriteFile(configFile, []byte(`{
		"listen": ":1111",
		"path": "/from-file",
		"upstreams": ["tls://1.1.1.1"],
		"timeout": "7s",
		"plaintext": true
	}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
		env  map[string]string
		want func(t *testing.T, c serve.Config)
	}{
		{
			name: "defaults leave fields unset",
			want: func(t *testing.T, c serve.Config) {
				if c.Listen != "" || c.Upstreams != nil || c.Plaintext {
					t.Errorf("got %+v, want zero config", c)
				}
			},
		},
		{
			name: "config file",
			args: []string{"--config", configFile},
			want: func(t *testing.T, c serve.Config) {
				if c.Listen != ":1111" || c.Path != "/from-file" || !c.Plaintext || time.Duration(c.Timeout) != 7*time.Second {
					t.Errorf("got %+v, want values from file", c)
				}
				if !slices.Equal(c.Upstreams, []string{"tls://1.1.1.1"}) {
					t.Errorf("got upstreams %v, want [tls://1.1.1.1]", c.Upstreams)
				}
			},
		},
		{
			name: "config file from environment",
			env:  map[string]string{"DOH_CONFIG": configFile},
			want: func(t *testing.T, c serve.Config) {
				if c.Listen != ":1111" {
					t.Errorf("got listen %q, want :1111", c.Listen)
				}
			},
		},
		{
			name: "environment overrides file",
			args: []string{"--config", configFile},
			env: map[string]string{
				"DOH_LISTEN":   ":2222",
				"DOH_UPSTREAM": "9.9.9.9,tcp://8.8.8.8",
				"DOH_TIMEOUT":  "3s",
			},
			want: func(t *testing.T, c serve.Config) {
				if c.Listen != ":2222" || time.Duration(c.Timeout) != 3*time.Second {
					t.Errorf("got %+v, want values from environment", c)
				}
				if !slices.Equal(c.Upstreams, []string{"9.9.9.9", "tcp://8.8.8.8"}) {
					t.Errorf("got upstreams %v, want [9.9.9.9 tcp://8.8.8.8]", c.Upstreams)
				}
				if c.Path != "/from-file" {
					t.Errorf("got path %q, want value from file", c.Path)
				}
			},
		},
		{
			name: "flags override environment",
			args: []string{"--config", configFile, "--listen", ":3333", "--acme-domain", "a.example,b.example"},
			env:  map[string]string{"DOH_LISTEN": ":2222"},
			want: func(t *testing.T, c serve.Config) {
				if c.Listen != ":3333" {
					t.Errorf("got listen %q, want :3333", c.Listen)
				}
				if !slices.Equal(c.TLS.ACME.Domains, []string{"a.example", "b.example"}) {
					t.Errorf("got domains %v", c.TLS.ACME.Domains)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for k, v := range test.env {
				t.Setenv(k, v)
			}

			fs := pflag.NewFlagSet("serve", pflag.ContinueOnError)
			defineServeFlags(fs)
			if err := fs.Parse(test.args); err != nil {
				t.Fatal(err)
			}

			config, err := loadServeConfig(fs)
			if err != nil {
				t.Fatal(err)
			}

			test.want(t, config)
		})
	}
}

func TestLoadServeConfig_Errors(t *testing.T) {
	t.Run("invalid environment value", func(t *testing.T) {
		t.Setenv("DOH_TIMEOUT", "soon")

		fs := pflag.NewFlagSet("serve", pflag.ContinueOnError)
		defineServeFlags(fs)

		if _, err := loadServeConfig(fs); err == nil {
			t.Fatal("expected error for invalid DOH_TIMEOUT")
		}
	})

	t.Run("unknown config field", func(t *testing.T) {
		configFile := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(configFile, []byte(`{"listne": ":1"}`), 0o600); err != nil {
			t.Fatal(err)
		}

		fs := pflag.NewFlagSet("serve", pflag.ContinueOnError)
		defineServeFlags(fs)
		if err := fs.Parse([]string{"--config", configFile}); err != nil {
			t.Fatal(err)
		}

		if _, err := loadServeConfig(fs); err == nil {
			t.Fatal("expected error for unknown field")
		}
	})

	t.Run("every serve flag is defined", func(t *testing.T) {
		fs := pflag.NewFlagSet("serve", pflag.ContinueOnError)
		defineServeFlags(fs)

		for name := range serveFlags {
			if fs.Lookup(name) == nil {
				t.Errorf("serveFlags has %q, but no such flag is defined", name)
			}
		}
	})
}
