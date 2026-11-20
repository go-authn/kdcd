// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Every refusal below is a pair: the valid configuration builds (the control),
// then ONE change to it is refused with a message naming the cause. A refusal
// test without its control passes just as well when the base is broken.
func TestConfigRefusals(t *testing.T) {
	cases := []struct {
		name   string
		modes  bool // needs Unix mode bits
		mutate func(e *env, s *spec)
		want   string
	}{
		{name: "no realm", mutate: func(e *env, s *spec) { s.Realm = "" }, want: "realm"},
		{name: "realm in lower case", mutate: func(e *env, s *spec) { s.Realm = "poc.test" }, want: "in capitals"},
		{name: "no keytab_file", mutate: func(e *env, s *spec) { s.KeytabFile = "" }, want: "keytab_file"},
		{name: "a secret written inline", mutate: func(e *env, s *spec) {
			s.Users = `user "dave" { password = "hunter2" }`
		}, want: "Unsupported argument"},
		{name: "an argument nobody defined", mutate: func(e *env, s *spec) { s.Extra = `krbtgt_key = "x"` }, want: "Unsupported argument"},
		{name: "wildcard kdc address", mutate: func(e *env, s *spec) { s.Listen = `address = "0.0.0.0:88"` }, want: "wildcard"},
		{name: "wildcard v6 kdc address", mutate: func(e *env, s *spec) { s.Listen = `address = "[::]:88"` }, want: "wildcard"},
		{name: "a name instead of an address", mutate: func(e *env, s *spec) { s.Listen = `address = "localhost:88"` }, want: "IP address"},
		{name: "no port", mutate: func(e *env, s *spec) { s.Listen = `address = "127.0.0.1"` }, want: "IP:port"},
		{name: "port out of range", mutate: func(e *env, s *spec) { s.Listen = `address = "127.0.0.1:70000"` }, want: "port"},
		{name: "wildcard mint address, even when the kdc may be", mutate: func(e *env, s *spec) {
			s.Listen = "address = \"127.0.0.1:0\"\n  allow_wildcard = true"
			s.Mint = strings.Replace(s.Mint, `"127.0.0.1:0"`, `"0.0.0.0:8443"`, 1)
		}, want: "name its interface"},
		{name: "services with no host", mutate: func(e *env, s *spec) { s.Services = `["cifs"]` }, want: "service/host"},
		{name: "services naming krbtgt", mutate: func(e *env, s *spec) { s.Services = `["krbtgt/POC.TEST"]` }, want: "krbtgt"},
		{name: "a service the keytab lacks", mutate: func(e *env, s *spec) { s.Services = `["cifs/fs.poc.test", "nfs/absent.poc.test"]` }, want: "nfs/absent.poc.test"},
		{name: "lifetime over a day", mutate: func(e *env, s *spec) { s.Extra = `lifetime = "48h"` }, want: "between"},
		{name: "lifetime that is not a duration", mutate: func(e *env, s *spec) { s.Extra = `lifetime = "ten hours"` }, want: "lifetime"},
		{name: "no directory", mutate: func(e *env, s *spec) { s.Users = "" }, want: "no directory"},
		{name: "a directory kind that does not exist", mutate: func(e *env, s *spec) { s.Users = `users "nis" {}` }, want: `no "nis" directory`},
		{name: "two people of one name", mutate: func(e *env, s *spec) { s.Users = "user \"a\" {}\nuser \"a\" {}" }, want: "twice"},

		{name: "keytab readable by its group", modes: true, mutate: func(e *env, s *spec) { chmod(t, e.keytab, 0o640) }, want: "group and others"},
		{name: "keytab readable by everybody", modes: true, mutate: func(e *env, s *spec) { chmod(t, e.keytab, 0o644) }, want: "group and others"},
		{name: "keytab writable by its group", modes: true, mutate: func(e *env, s *spec) { chmod(t, e.keytab, 0o620) }, want: "group and others"},
		{name: "keytab that is a directory", mutate: func(e *env, s *spec) { s.KeytabFile = e.dir }, want: "not a regular file"},
		{name: "keytab that is missing", mutate: func(e *env, s *spec) { s.KeytabFile = filepath.Join(e.dir, "absent") }, want: "absent"},
		{name: "keytab that is empty", mutate: func(e *env, s *spec) {
			writeFile(t, e.keytab, nil, 0o600)
		}, want: "keytab"},
		{name: "keytab that is not one", mutate: func(e *env, s *spec) {
			writeFile(t, e.keytab, []byte("not a keytab at all, just text"), 0o600)
		}, want: "keytab"},
		{name: "keytab for another realm", mutate: func(e *env, s *spec) {
			writeFile(t, e.keytab, newKeytab(t, "OTHER.TEST", "krbtgt/OTHER.TEST", "cifs/fs.poc.test"), 0o600)
		}, want: "krbtgt/POC.TEST"},
		{name: "keytab with no krbtgt", mutate: func(e *env, s *spec) {
			writeFile(t, e.keytab, newKeytab(t, testRealm, "cifs/fs.poc.test"), 0o600)
		}, want: "krbtgt/POC.TEST"},

		{name: "mint key readable by its group", modes: true, mutate: func(e *env, s *spec) { chmod(t, e.keyFile, 0o640) }, want: "key_file"},
		{name: "mint key readable by everybody", modes: true, mutate: func(e *env, s *spec) { chmod(t, e.keyFile, 0o644) }, want: "group and others"},
		{name: "mint without callers", mutate: func(e *env, s *spec) {
			s.Mint = strings.Replace(s.Mint, fmt.Sprintf("%q", testCaller), "", 1)
		}, want: "callers is empty"},
		{name: "a caller that is not a URI", mutate: func(e *env, s *spec) {
			s.Mint = strings.Replace(s.Mint, testCaller, "login.poc.test", 1)
		}, want: "absolute URI"},
		{name: "a caller with a wildcard", mutate: func(e *env, s *spec) {
			s.Mint = strings.Replace(s.Mint, testCaller, "https://*.poc.test", 1)
		}, want: "wildcard"},
		{name: "mint with no certificate", mutate: func(e *env, s *spec) {
			s.Mint = strings.Replace(s.Mint, fmt.Sprintf("cert_file      = %q", e.certFile), "", 1)
		}, want: "cert_file"},
		{name: "a client CA that holds no certificate", mutate: func(e *env, s *spec) {
			writeFile(t, e.clientCA, []byte("nothing"), 0o644)
		}, want: "holds no certificate"},
		{name: "a certificate that does not match its key", mutate: func(e *env, s *spec) {
			other := e.ca.issue(t, true, nil, time.Now().Add(time.Hour))
			writeFile(t, e.keyFile, other.keyPEM, 0o600)
		}, want: "cert_file and key_file"},
		{name: "an expired mint certificate", mutate: func(e *env, s *spec) {
			old := e.ca.issue(t, true, nil, time.Now().Add(-time.Minute))
			writeFile(t, e.certFile, old.certPEM, 0o644)
			writeFile(t, e.keyFile, old.keyPEM, 0o600)
		}, want: "is valid from"},

		{name: "a password file readable by its group", modes: true, mutate: func(e *env, s *spec) { chmod(t, e.alicePW, 0o640) }, want: "password_file"},
		{name: "an empty password file", mutate: func(e *env, s *spec) { writeFile(t, e.alicePW, []byte("\n"), 0o600) }, want: "is empty"},
		{name: "a dsn file readable by everybody", modes: true, mutate: func(e *env, s *spec) {
			dsn := writeFile(t, filepath.Join(e.dir, "dsn"), []byte("file:"+filepath.Join(e.dir, "d.db")), 0o644)
			s.Users = sqliteBlock(dsn)
		}, want: "dsn_file"},
		{name: "a ldap bind password readable by everybody", modes: true, mutate: func(e *env, s *spec) {
			pw := writeFile(t, filepath.Join(e.dir, "bind.pw"), []byte("x"), 0o644)
			s.Users = fmt.Sprintf("users \"ldap\" {\n url = \"ldaps://127.0.0.1:1\"\n base_dn = \"dc=x\"\n bind_dn = \"cn=r,dc=x\"\n bind_password_file = %q\n}", pw)
		}, want: "bind_password_file"},
		{name: "a ldap url that sends passwords in the clear", mutate: func(e *env, s *spec) {
			s.Users = "users \"ldap\" {\n url = \"ldap://ldap.example.org\"\n base_dn = \"dc=x\"\n}"
		}, want: "in the clear"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.modes {
				skipWithoutModes(t)
			}
			// The control: the same files and the same configuration, unchanged.
			ctl := newEnv(t)
			rt, err := ctl.build(ctl.spec())
			if err != nil {
				t.Fatalf("the control does not build: %v", err)
			}
			rt.Close()

			e := newEnv(t)
			s := e.spec()
			c.mutate(e, s)
			rt, err = e.build(s)
			if err == nil {
				rt.Close()
				t.Fatalf("accepted; want an error containing %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err, c.want)
			}
		})
	}
}

func chmod(t *testing.T, path string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, m); err != nil {
		t.Fatal(err)
	}
}

func sqliteBlock(dsn string) string {
	return fmt.Sprintf("users \"sql\" {\n driver = \"sqlite\"\n dsn_file = %q\n users = \"select 'erin' as name\"\n}", dsn)
}

// What is allowed stays allowed: the refusals above must not have become
// refusals of everything near them.
func TestConfigAccepts(t *testing.T) {
	t.Run("keytab at 0400 and 0600", func(t *testing.T) {
		skipWithoutModes(t)
		e := newEnv(t)
		for _, m := range []os.FileMode{0o400, 0o600} {
			chmod(t, e.keytab, m)
			rt, err := e.build(e.spec())
			if err != nil {
				t.Fatalf("mode %04o: %v", m, err)
			}
			rt.Close()
		}
	})
	t.Run("a wildcard when it is asked for", func(t *testing.T) {
		e := newEnv(t)
		s := e.spec()
		s.Listen = "address = \"0.0.0.0:0\"\n  allow_wildcard = true"
		cfg, err := LoadConfig(e.write(s))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.KDCAddr != "0.0.0.0:0" {
			t.Fatalf("address %q", cfg.KDCAddr)
		}
	})
	t.Run("the default address is the loopback", func(t *testing.T) {
		e := newEnv(t)
		s := e.spec()
		s.Listen = ""
		s.Mint = ""
		cfg, err := LoadConfig(e.write(s))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.KDCAddr != "127.0.0.1:88" || cfg.Mint != nil {
			t.Fatalf("address %q, mint %v", cfg.KDCAddr, cfg.Mint)
		}
	})
	t.Run("the default mint address is the loopback", func(t *testing.T) {
		e := newEnv(t)
		s := e.spec()
		s.Mint = strings.Replace(s.Mint, "  address        = \"127.0.0.1:0\"\n", "", 1)
		cfg, err := LoadConfig(e.write(s))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Mint.Addr != "127.0.0.1:8443" {
			t.Fatalf("mint address %q", cfg.Mint.Addr)
		}
	})
	t.Run("a sqlite directory", func(t *testing.T) {
		e := newEnv(t)
		dsn := writeFile(t, filepath.Join(e.dir, "dsn"), []byte("file:"+filepath.Join(e.dir, "d.db")), 0o600)
		s := e.spec()
		s.Users = sqliteBlock(dsn)
		rt, err := e.build(s)
		if err != nil {
			t.Fatal(err)
		}
		rt.Close()
	})
}

// A configuration file that others can write decides who may mint.
func TestConfigFileWritableByOthersIsRefused(t *testing.T) {
	skipWithoutModes(t)
	e := newEnv(t)
	path := e.write(e.spec())
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("the control: %v", err)
	}
	chmod(t, path, 0o664)
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "must not be able to write") {
		t.Fatalf("got %v", err)
	}
}

// A keytab owned by somebody else is refused even at mode 0600: its owner can
// change the mode, or the keys. Needs a non-root owner to be told apart from
// root, whom the rule trusts.
func TestKeytabOfAnotherOwnerIsRefused(t *testing.T) {
	skipWithoutModes(t)
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("the file's owner is root, whom the rule accepts")
	}
	e := newEnv(t)
	if _, err := readKeytab(e.keytab); err != nil {
		t.Fatalf("the control: %v", err)
	}
	old := euid
	euid = func() int { return os.Geteuid() + 1 }
	defer func() { euid = old }()
	_, err := readKeytab(e.keytab)
	if err == nil || !strings.Contains(err.Error(), "neither root nor this daemon") {
		t.Fatalf("got %v", err)
	}
}

func TestKeytabTooLargeIsRefused(t *testing.T) {
	e := newEnv(t)
	if _, err := readKeytab(e.keytab); err != nil {
		t.Fatalf("the control: %v", err)
	}
	writeFile(t, e.keytab, make([]byte, maxSecret+1), 0o600)
	_, err := readKeytab(e.keytab)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}
