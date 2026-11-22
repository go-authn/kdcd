// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-authn/directory/hcldir"
)

// Suspicion 4a. The configuration file decides who may mint tickets, and its
// mode was checked but not its owner: another account owning it can chmod it
// writable again after the check.
func TestConfigFileOfAnotherOwnerIsRefused(t *testing.T) {
	skipWithoutModes(t)
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("the file's owner is root, whom the rule accepts")
	}
	path := writeFile(t, filepath.Join(t.TempDir(), "kdcd.hcl"), []byte("realm = \"X\"\n"), 0o600)
	if _, err := readConfigFile(path); err != nil {
		t.Fatalf("the control: %v", err)
	}
	old := euid
	euid = func() int { return os.Geteuid() + 1 }
	defer func() { euid = old }()
	_, err := readConfigFile(path)
	if err == nil || !strings.Contains(err.Error(), "neither root nor this daemon") {
		t.Fatalf("got %v", err)
	}
}

// Suspicion 4b. The DSN file was checked by name and then opened again by
// name by the directory library. A path swapped between the two made the
// daemon use a file nothing had checked.
func TestTheDSNOpenedIsTheDSNChecked(t *testing.T) {
	skipWithoutModes(t)
	if runtime.GOOS == "windows" {
		t.Skip("no descriptor namespace")
	}
	dir := t.TempDir()
	good := "file:" + filepath.Join(dir, "d.db")
	dsn := writeFile(t, filepath.Join(dir, "dsn"), []byte(good), 0o600)
	// What an attacker puts in its place: a DSN that cannot be opened.
	evil := writeFile(t, filepath.Join(dir, "evil"), []byte("file:"+filepath.Join(dir, "no", "such", "dir", "x.db")), 0o600)
	blk := hcldir.Block{Kind: "sql", Driver: "sqlite", DSNFile: dsn, UsersQuery: "select 'erin' as name"}

	src, err := openPeople(&Config{Users: []hcldir.Block{blk}})
	if err != nil {
		t.Fatalf("the control: %v", err)
	}
	closeSource(src)

	afterDSNCheck = func() {
		if err := os.Rename(evil, dsn); err != nil {
			t.Error(err)
		}
	}
	defer func() { afterDSNCheck = func() {} }()
	src, err = openPeople(&Config{Users: []hcldir.Block{blk}})
	if err != nil {
		t.Fatalf("the file read was not the file checked: %v", err)
	}
	closeSource(src)
}

// A DSN file that is missing, or names a database that does not answer, is a
// refusal that says which block it is.
func TestADSNThatCannotBeUsedIsRefused(t *testing.T) {
	dir := t.TempDir()
	blk := hcldir.Block{Kind: "sql", Driver: "sqlite", DSNFile: filepath.Join(dir, "missing"), UsersQuery: "select 'erin' as name"}
	if _, err := openPeople(&Config{Users: []hcldir.Block{blk}}); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("a missing DSN file: %v", err)
	}
	blk.DSNFile = writeFile(t, filepath.Join(dir, "dsn"), []byte("file:"+filepath.Join(dir, "absent.db")+"?mode=ro"), 0o600)
	if _, err := openPeople(&Config{Users: []hcldir.Block{blk}}); err == nil || !strings.Contains(err.Error(), `users "sql"`) {
		t.Fatalf("a database that does not answer: %v", err)
	}
}

func closeSource(s interface{}) {
	if c, ok := s.(interface{ Close() error }); ok {
		c.Close()
	}
}
