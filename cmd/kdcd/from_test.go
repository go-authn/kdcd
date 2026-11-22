// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-authn/secretsource"
)

// credDir stands in for what the service manager places for
// LoadCredentialEncrypted=: a directory of the caller's, 0700, that holds one
// file per credential, 0600.
func credDir(t *testing.T, files map[string][]byte) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("systemd-creds: resolves on Linux only")
	}
	dir := filepath.Join(t.TempDir(), "creds")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, b := range files {
		writeFile(t, filepath.Join(dir, name), b, 0o600)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
}

// keytab_from and key_from name a secretsource reference; the secret is not in
// the configuration, and the daemon builds from what the reference resolves to.
func TestAReferenceResolves(t *testing.T) {
	e := newEnv(t)
	keyPEM, err := os.ReadFile(e.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	kt, err := os.ReadFile(e.keytab)
	if err != nil {
		t.Fatal(err)
	}
	credDir(t, map[string][]byte{"kdc-keytab": kt, "mint-key": keyPEM})

	s := e.spec()
	s.KeytabFile = ""
	s.Extra = `keytab_from = "systemd-creds:kdc-keytab"`
	s.Mint = fmt.Sprintf(`mint {
  address        = "127.0.0.1:0"
  cert_file      = %q
  key_from       = "systemd-creds:mint-key"
  client_ca_file = %q
  callers        = [%q]
}`, e.certFile, e.clientCA, testCaller)
	rt, err := e.build(s)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if rt.Keytab == nil || len(rt.Keytab.Entries) != 2 || rt.TLS == nil {
		t.Fatalf("keytab %v, tls %v", rt.Keytab, rt.TLS)
	}
}

// `kdcd check` prints the reference, never what it resolved to.
func TestAReferenceCheckShowsTheReferenceNotTheSecret(t *testing.T) {
	e := newEnv(t)
	kt, _ := os.ReadFile(e.keytab)
	credDir(t, map[string][]byte{"kdc-keytab": kt})
	s := e.spec()
	s.KeytabFile = ""
	s.Mint = ""
	s.Extra = `keytab_from = "systemd-creds:kdc-keytab"`
	rt, err := e.build(s)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if out := rt.Summary(); !strings.Contains(out, "systemd-creds:kdc-keytab") {
		t.Fatalf("the report does not name the reference:\n%s", out)
	}
}

func TestBothKeytabInputsAreRefused(t *testing.T) {
	e := newEnv(t)
	s := e.spec()
	s.Extra = `keytab_from = "systemd-creds:kdc-keytab"`
	_, err := e.build(s)
	if err == nil || !strings.Contains(err.Error(), "keytab_file and keytab_from are both set") {
		t.Fatalf("got %v", err)
	}
}

func TestBothMintKeyInputsAreRefused(t *testing.T) {
	e := newEnv(t)
	s := e.spec()
	s.Mint = fmt.Sprintf(`mint {
  address        = "127.0.0.1:0"
  cert_file      = %q
  key_file       = %q
  key_from       = "systemd-creds:mint-key"
  client_ca_file = %q
  callers        = [%q]
}`, e.certFile, e.keyFile, e.clientCA, testCaller)
	_, err := e.build(s)
	if err == nil || !strings.Contains(err.Error(), "key_file and key_from are both set") {
		t.Fatalf("got %v", err)
	}
}

// The path forms are not deprecated: they are the readers that keep binary
// material intact, and the tests above already build from them (newEnv). The
// control here is that neither being set is refused too.
func TestNoKeytabSourceIsRefused(t *testing.T) {
	e := newEnv(t)
	s := e.spec()
	s.KeytabFile = ""
	_, err := e.build(s)
	if err == nil || !strings.Contains(err.Error(), "keytab_file is empty") {
		t.Fatalf("got %v", err)
	}
}

func TestAFileReferenceIsNotAcceptedInFrom(t *testing.T) {
	e := newEnv(t)
	s := e.spec()
	s.KeytabFile = ""
	s.Extra = fmt.Sprintf("keytab_from = %q", "file:"+e.keytab)
	_, err := e.build(s)
	if err == nil || !strings.Contains(err.Error(), "write the path as keytab_file") {
		t.Fatalf("got %v", err)
	}
}

func TestAReferenceWithNoSchemeIsRefused(t *testing.T) {
	e := newEnv(t)
	s := e.spec()
	s.KeytabFile = ""
	s.Extra = fmt.Sprintf("keytab_from = %q", e.keytab)
	_, err := e.build(s)
	if err == nil || !strings.Contains(err.Error(), "keytab_from") {
		t.Fatalf("got %v", err)
	}
}

// An oversized secret is refused by the resolver (secretsource.MaxSize), and the
// message points the operator at keytab_file, which reads up to maxSecret.
func TestAnOversizedReferenceIsRefused(t *testing.T) {
	e := newEnv(t)
	credDir(t, map[string][]byte{"kdc-keytab": make([]byte, secretsource.MaxSize+1)})
	s := e.spec()
	s.KeytabFile = ""
	s.Mint = ""
	s.Extra = `keytab_from = "systemd-creds:kdc-keytab"`
	_, err := e.build(s)
	if !errors.Is(err, secretsource.ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
}

// A credential that is not there fails the build; nothing falls back to a file.
func TestAMissingCredentialFailsTheBuild(t *testing.T) {
	e := newEnv(t)
	credDir(t, map[string][]byte{"other": []byte("x")})
	s := e.spec()
	s.KeytabFile = ""
	s.Mint = ""
	s.Extra = `keytab_from = "systemd-creds:kdc-keytab"`
	if _, err := e.build(s); err == nil {
		t.Fatal("built without the credential")
	}
}

// Platform-independent: where() names the reference when there is one, and a
// reference that parses but cannot be opened is an error, never an empty secret.
func TestKeyMaterialWhereAndUnopenable(t *testing.T) {
	if got := (keyMaterial{From: "systemd-creds:a"}).where(); got != "systemd-creds:a" {
		t.Fatalf("where = %q", got)
	}
	if got := (keyMaterial{File: "/p"}).where(); got != "/p" {
		t.Fatalf("where = %q", got)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", t.TempDir())
	b, err := readKeyMaterial(keyMaterial{From: "systemd-creds:absent"}, "keytab")
	if err == nil || len(b) != 0 {
		t.Fatalf("got %d bytes, %v", len(b), err)
	}
}

// A reference with no scheme is refused when the configuration is loaded,
// before anything is opened.
func TestAReferenceWithNoSchemeIsRefusedAtLoad(t *testing.T) {
	e := newEnv(t)
	s := e.spec()
	s.KeytabFile = ""
	s.Extra = fmt.Sprintf("keytab_from = %q", e.keytab)
	_, err := LoadConfig(e.write(s))
	if !errors.Is(err, secretsource.ErrScheme) && !errors.Is(err, secretsource.ErrBadRef) {
		t.Fatalf("got %v", err)
	}
}
