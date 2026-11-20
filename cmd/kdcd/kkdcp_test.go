// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

const kkdcpBlockText = `kkdcp {
  listen = "127.0.0.1:0"
}`

// kkdcpEnvelope is what a KKDCP client posts: KDC-PROXY-MESSAGE, written here
// from MS-KKDCP 2.2.2 and not borrowed from the library under test.
func kkdcpEnvelope(t *testing.T, msg []byte, realm string) []byte {
	t.Helper()
	k := binary.BigEndian.AppendUint32(nil, uint32(len(msg)))
	k = append(k, msg...)
	b, err := asn1.Marshal(struct {
		KerbMessage  []byte `asn1:"explicit,tag:0"`
		TargetDomain string `asn1:"explicit,tag:1,optional,generalstring"`
	}{k, realm})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// asReqFor is the AS-REQ a client sends first for a person: no pre-authentication.
func asReqFor(t *testing.T, who string) []byte {
	t.Helper()
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = testRealm
	name := types.NewPrincipalName(1, who)
	req, err := messages.NewASReqForTGT(testRealm, cfg, name)
	if err != nil {
		t.Fatal(err)
	}
	b, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func post(t *testing.T, url string, body []byte) (int, []byte) {
	t.Helper()
	resp, err := http.Post(url, "application/kerberos", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// With a kkdcp block the daemon answers MS-KKDCP on its own listener, the same
// answers port 88 gives: the person with no key is KDC_ERR_NULL_KEY and a
// stranger is not, each beside the refusals of the envelope itself.
func TestKKDCPListener(t *testing.T) {
	e := newEnv(t)
	s := e.spec()
	s.Extra = kkdcpBlockText
	d := e.start(s)
	if d.KKDCPAddr() == "" {
		t.Fatal("no kkdcp listener")
	}
	url := "http://" + d.KKDCPAddr() + defaultKKDCPPath

	codeOf := func(who string) int32 {
		t.Helper()
		status, body := post(t, url, kkdcpEnvelope(t, asReqFor(t, who), testRealm))
		if status != http.StatusOK {
			t.Fatalf("%s: status %d: %s", who, status, body)
		}
		var env struct {
			KerbMessage []byte `asn1:"explicit,tag:0"`
		}
		if rest, err := asn1.Unmarshal(body, &env); err != nil || len(rest) != 0 || len(env.KerbMessage) < 4 {
			t.Fatalf("%s: not a KDC-PROXY-MESSAGE: %v", who, err)
		}
		var ke messages.KRBError
		if err := ke.Unmarshal(env.KerbMessage[4:]); err != nil {
			t.Fatalf("%s: not a KRB-ERROR: %v", who, err)
		}
		return ke.ErrorCode
	}
	alice, mallory := codeOf("alice"), codeOf("mallory")
	if alice != 9 { // KDC_ERR_NULL_KEY
		t.Errorf("alice (no key): code %d, want 9", alice)
	}
	if mallory != 6 { // KDC_ERR_C_PRINCIPAL_UNKNOWN
		t.Errorf("mallory (a stranger): code %d, want 6", mallory)
	}

	if status, _ := post(t, url, []byte("junk")); status != http.StatusBadRequest {
		t.Errorf("junk: %d, want 400", status)
	}
	if status, _ := post(t, url, kkdcpEnvelope(t, asReqFor(t, "alice"), "OTHER.TEST")); status != http.StatusForbidden {
		t.Errorf("another realm: %d, want 403", status)
	}
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d, want 405", resp.StatusCode)
	}
	// Only the one path is served.
	resp, err = http.Post("http://"+d.KKDCPAddr()+"/", "application/kerberos", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("another path: %d, want 404", resp.StatusCode)
	}
}

func TestNoKKDCPBlockNoKKDCPListener(t *testing.T) {
	e := newEnv(t)
	d := e.start(e.spec())
	if d.KKDCPAddr() != "" {
		t.Fatalf("a kkdcp listener without a block: %s", d.KKDCPAddr())
	}
}

func TestKKDCPPathIsConfigurable(t *testing.T) {
	e := newEnv(t)
	s := e.spec()
	s.Extra = "kkdcp {\n  listen = \"127.0.0.1:0\"\n  path = \"/kerberos/proxy\"\n}"
	d := e.start(s)
	if status, _ := post(t, "http://"+d.KKDCPAddr()+"/kerberos/proxy", kkdcpEnvelope(t, asReqFor(t, "alice"), testRealm)); status != http.StatusOK {
		t.Errorf("the configured path: %d", status)
	}
	if status, _ := post(t, "http://"+d.KKDCPAddr()+defaultKKDCPPath, kkdcpEnvelope(t, asReqFor(t, "alice"), testRealm)); status != http.StatusNotFound {
		t.Errorf("the default path when another is set: %d, want 404", status)
	}
}

func TestKKDCPConfigRefusals(t *testing.T) {
	e := newEnv(t)
	good := e.spec()
	good.Extra = kkdcpBlockText
	if _, err := e.build(good); err != nil {
		t.Fatalf("the control: %v", err)
	}
	for name, tc := range map[string]struct{ block, want string }{
		"a wildcard":            {"kkdcp {\n listen = \"0.0.0.0:8088\"\n}", "wildcard"},
		"a name":                {"kkdcp {\n listen = \"localhost:8088\"\n}", "IP address"},
		"no listen":             {"kkdcp {\n}", "listen"},
		"a pattern in path":     {"kkdcp {\n listen = \"127.0.0.1:8088\"\n path = \"/{x}\"\n}", "path"},
		"a subtree path":        {"kkdcp {\n listen = \"127.0.0.1:8088\"\n path = \"/KdcProxy/\"\n}", "path"},
		"a relative path":       {"kkdcp {\n listen = \"127.0.0.1:8088\"\n path = \"KdcProxy\"\n}", "path"},
		"a dot-dot path":        {"kkdcp {\n listen = \"127.0.0.1:8088\"\n path = \"/a/../b\"\n}", "path"},
		"the kdc's own address": {"kkdcp {\n listen = \"127.0.0.1:88\"\n}", "another listener"},
	} {
		s := e.spec()
		s.Listen = ""
		s.Extra = tc.block
		_, err := e.build(s)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error naming %q", name, err, tc.want)
		}
	}
}

func TestCheckPrintsTheKKDCPBlock(t *testing.T) {
	e := newEnv(t)
	s := e.spec()
	out, _, err := run("check", "--config", e.write(s))
	if err != nil || !strings.Contains(out, "kkdcp        off") {
		t.Fatalf("without a block: %v\n%s", err, out)
	}
	s.Extra = "kkdcp {\n  listen = \"127.0.0.1:8088\"\n}"
	out, _, err = run("check", "--config", e.write(s))
	if err != nil || !strings.Contains(out, "kkdcp        http://127.0.0.1:8088/KdcProxy") {
		t.Fatalf("with a block: %v\n%s", err, out)
	}
}
