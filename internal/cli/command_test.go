package cli_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/picatz/doh/internal/cli"
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
			name: "google.com",
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
			name: "cloudflare.com",
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
