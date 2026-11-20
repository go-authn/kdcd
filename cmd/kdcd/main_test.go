// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func run(args ...string) (stdout, stderr string, err error) {
	var o, e bytes.Buffer
	cmd := RootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&o)
	cmd.SetErr(&e)
	err = cmd.Execute()
	return o.String(), e.String(), err
}

func TestCheckPrintsASummary(t *testing.T) {
	e := newEnv(t)
	path := e.write(e.spec())
	out, _, err := run("check", "--config", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"realm        POC.TEST",
		"krbtgt/POC.TEST@POC.TEST kvno 3 etype 18",
		"cifs/fs.poc.test@POC.TEST",
		"people     2",
		"caller     " + testCaller,
		"ok\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	// ⛔ A summary names keys, never prints one.
	kt, _ := os.ReadFile(e.keytab)
	if bytes.Contains([]byte(out), kt[:16]) {
		t.Errorf("the summary holds a secret:\n%s", out)
	}
}

func TestCheckRefusesABadConfiguration(t *testing.T) {
	skipWithoutModes(t)
	e := newEnv(t)
	path := e.write(e.spec())
	if _, _, err := run("check", "--config", path); err != nil {
		t.Fatalf("the control: %v", err)
	}
	chmod(t, e.keytab, 0o644)
	_, _, err := run("check", "--config", path)
	if err == nil || !strings.Contains(err.Error(), "group and others") {
		t.Fatalf("got %v", err)
	}
}

func TestConfigIsRequired(t *testing.T) {
	for _, args := range [][]string{{"check"}, {}} {
		_, _, err := run(args...)
		if err == nil || !strings.Contains(err.Error(), "--config is required") {
			t.Errorf("%v: got %v", args, err)
		}
	}
}

func TestVersion(t *testing.T) {
	out, _, err := run("--version")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^kdcd \S+\n$`).MatchString(out) {
		t.Fatalf("got %q", out)
	}
}

func TestNoPositionalArguments(t *testing.T) {
	if _, _, err := run("serve"); err == nil {
		t.Fatal("an unknown subcommand was accepted")
	}
}

// main exits 1 with the reason on stderr; osExit is the seam.
func TestMainExitsNonZeroOnAnError(t *testing.T) {
	var code = -1
	oldExit, oldArgs := osExit, os.Args
	osExit = func(c int) { code = c }
	os.Args = []string{"kdcd", "check", "--config", filepath.Join(t.TempDir(), "absent.hcl")}
	defer func() { osExit, os.Args = oldExit, oldArgs }()
	main()
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
}

// The whole program: `kdcd --config` serves until its context ends, then
// returns nil.
func TestRunServesAndStops(t *testing.T) {
	e := newEnv(t)
	path := e.write(e.spec())
	var out, errb lockedBuffer
	cmd := RootCmd()
	cmd.SetArgs([]string{"--config", path})
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()

	re := regexp.MustCompile(`kdc on (127\.0\.0\.1:\d+) \(tcp and udp\)`)
	var addr string
	deadline := time.Now().Add(10 * time.Second)
	for addr == "" && time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(out.String()); m != nil {
			addr = m[1]
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if addr == "" {
		t.Fatalf("it never said where it listens; stdout %q stderr %q", out.String(), errb.String())
	}
	// The program answers: a person has no key, and it says so.
	cl := krbClient(t, addr, "alice", "anything", true)
	if err := cl.Login(); err == nil || !strings.Contains(err.Error(), "NULL_KEY") {
		t.Fatalf("AS exchange against the program: %v, want KDC_ERR_NULL_KEY", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stopped with %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("did not stop")
	}
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Fatalf("%s still answers after the program returned", addr)
	}
}

// Installed as `go install` installs it, the binary is kdcd and nothing else
// is a main package (krb5kdc is MIT's, kdc is Heimdal's).
func TestTheBinaryIsNamedKdcd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the program")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	cmd := exec.Command("go", "build", "-trimpath", "-o", out+string(filepath.Separator), "./cmd/kdcd")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	ents, err := os.ReadDir(out)
	if err != nil || len(ents) != 1 {
		t.Fatalf("built %v, %v", ents, err)
	}
	if n := strings.TrimSuffix(ents[0].Name(), ".exe"); n != "kdcd" {
		t.Fatalf("the binary is named %q", n)
	}
}
