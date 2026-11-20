// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

const (
	testRealm  = "POC.TEST"
	testCaller = "https://login.poc.test"
)

// --- files ---

// writeFile writes with an exact mode: os.WriteFile's is masked by the umask.
func writeFile(t testing.TB, path string, data []byte, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func newKeytab(t testing.TB, realm string, principals ...string) []byte {
	t.Helper()
	kt := keytab.New()
	for _, p := range principals {
		// One key per principal, derived from a secret that is a test's.
		if err := kt.AddEntry(p, realm, "key of "+p, time.Now(), 3, etypeAES256); err != nil {
			t.Fatal(err)
		}
	}
	b, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// skipWithoutModes skips a test that needs Unix mode bits.
func skipWithoutModes(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no mode bits to refuse on; the README says where the ACLs go")
	}
}

// --- a throwaway PKI ---

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t testing.TB, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf is a certificate and its key, PEM and parsed.
type leaf struct {
	certPEM, keyPEM []byte
	pair            tls.Certificate
}

// issue signs a leaf. A server gets a 127.0.0.1 address; a client, the URIs.
func (ca *testCA) issue(t testing.TB, server bool, uris []string, notAfter time.Time) leaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if server {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		for _, u := range uris {
			pu, err := url.Parse(u)
			if err != nil {
				t.Fatal(err)
			}
			tpl.URIs = append(tpl.URIs, pu)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	l := leaf{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}),
	}
	l.pair, err = tls.X509KeyPair(l.certPEM, l.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// --- a configuration ---

// env is a directory of valid files for realm POC.TEST: a keytab holding
// krbtgt and cifs, and the mint listener's certificates.
type env struct {
	t           *testing.T
	dir         string
	keytab      string
	certFile    string
	keyFile     string
	clientCA    string
	ca          *testCA // signs the mint listener's certificate
	callersCA   *testCA // signs the callers' certificates
	serverCert  leaf
	goodCaller  leaf
	otherCaller leaf // good CA, a URI that is not on the list
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{t: t, dir: dir}
	e.keytab = writeFile(t, filepath.Join(dir, "kdc.keytab"),
		newKeytab(t, testRealm, "krbtgt/"+testRealm, "cifs/fs.poc.test"), 0o600)
	e.ca = newCA(t, "mint server CA")
	e.callersCA = newCA(t, "callers CA")
	e.serverCert = e.ca.issue(t, true, nil, time.Now().Add(time.Hour))
	e.goodCaller = e.callersCA.issue(t, false, []string{testCaller}, time.Now().Add(time.Hour))
	e.otherCaller = e.callersCA.issue(t, false, []string{"https://not-listed.poc.test"}, time.Now().Add(time.Hour))
	e.certFile = writeFile(t, filepath.Join(dir, "mint.pem"), e.serverCert.certPEM, 0o644)
	e.keyFile = writeFile(t, filepath.Join(dir, "mint.key"), e.serverCert.keyPEM, 0o600)
	e.clientCA = writeFile(t, filepath.Join(dir, "callers-ca.pem"), e.callersCA.pem, 0o644)
	return e
}

// spec is a configuration to render; a test changes a field and renders again.
type spec struct {
	Realm      string
	KeytabFile string
	Services   string // the HCL list, with brackets
	Listen     string // the body of the listen block, "" for none
	Mint       string // the whole mint block, "" for none
	Users      string // directory blocks
	Extra      string // anything else, at the top level
}

func (e *env) spec() *spec {
	return &spec{
		Realm:      testRealm,
		KeytabFile: e.keytab,
		Services:   `["cifs/fs.poc.test"]`,
		Listen:     `address = "127.0.0.1:0"`,
		Mint: fmt.Sprintf(`mint {
  address        = "127.0.0.1:0"
  cert_file      = %q
  key_file       = %q
  client_ca_file = %q
  callers        = [%q]
}`, e.certFile, e.keyFile, e.clientCA, testCaller),
		Users: "user \"alice\" {}\nuser \"carol\" {}\n",
	}
}

func (s *spec) hcl() string {
	var b strings.Builder
	if s.Realm != "" {
		fmt.Fprintf(&b, "realm = %q\n", s.Realm)
	}
	if s.KeytabFile != "" {
		fmt.Fprintf(&b, "keytab_file = %q\n", s.KeytabFile)
	}
	if s.Services != "" {
		fmt.Fprintf(&b, "services = %s\n", s.Services)
	}
	if s.Listen != "" {
		fmt.Fprintf(&b, "listen {\n  %s\n}\n", s.Listen)
	}
	b.WriteString(s.Mint + "\n" + s.Users + "\n" + s.Extra + "\n")
	return b.String()
}

// write renders s to a file in the env's directory and returns its path.
func (e *env) write(s *spec) string {
	e.t.Helper()
	return writeFile(e.t, filepath.Join(e.dir, "kdcd.hcl"), []byte(s.hcl()), 0o600)
}

// build loads and builds s as `kdcd` would, without listening.
func (e *env) build(s *spec) (*Runtime, error) {
	e.t.Helper()
	cfg, err := LoadConfig(e.write(s))
	if err != nil {
		return nil, err
	}
	return Build(cfg)
}

// start builds and listens, and shuts down at the end of the test.
func (e *env) start(s *spec) *Daemon {
	e.t.Helper()
	rt, err := e.build(s)
	if err != nil {
		e.t.Fatal(err)
	}
	d, err := Start(rt, e.t.Logf)
	if err != nil {
		rt.Close()
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		d.Shutdown(ctx)
	})
	return d
}

// lockedBuffer is a bytes.Buffer a test can read while a command writes to it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
