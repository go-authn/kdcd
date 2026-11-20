// SPDX-License-Identifier: BSD-3-Clause

package kdcd_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The program is installed as kdcd: `go install` names the binary after the
// last element of the package path, so a main package at the module root would
// be installed as `kdcd` only by accident of the module name, and any other
// directory under another name. Only cmd/kdcd may be a main package.
func TestTheMainPackageLivesAtCmdKdcd(t *testing.T) {
	var mains []string
	err := filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			// A Windows checkout may have CRLF line ends.
			src := strings.ReplaceAll(string(b), "\r\n", "\n")
			if strings.Contains(src, "\npackage main\n") || strings.HasPrefix(src, "package main\n") {
				mains = append(mains, filepath.ToSlash(filepath.Dir(p)))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range mains {
		if dir != "cmd/kdcd" {
			t.Errorf("a main package at %q: only cmd/kdcd may be one", dir)
		}
	}
	if len(mains) == 0 {
		t.Error("no main package found: expected cmd/kdcd")
	}
	if _, err := os.Stat("main.go"); err == nil {
		t.Error("main.go at the module root")
	}
}
