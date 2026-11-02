// Command genicons writes the web UI's app icons, drawn by
// [brand.AppIcons], to a directory: "go generate ./internal/brand" writes
// them to internal/webui/static.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/picatz/doh/internal/brand"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: genicons DIR")
		os.Exit(2)
	}
	icons, err := brand.AppIcons()
	if err != nil {
		fmt.Fprintln(os.Stderr, "genicons:", err)
		os.Exit(1)
	}
	for _, icon := range icons {
		if err := os.WriteFile(filepath.Join(os.Args[1], icon.Name), icon.PNG, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "genicons:", err)
			os.Exit(1)
		}
	}
}
