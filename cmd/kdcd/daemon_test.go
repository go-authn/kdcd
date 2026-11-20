// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
)

// krbClient is a gokrb5 client for one person at the daemon's address. tcp
// forces TCP (a UDP preference limit of 1 byte); otherwise it tries UDP first,
// as MIT's kinit does.
func krbClient(t *testing.T, addr, user, password string, tcp bool) *client.Client {
	t.Helper()
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = testRealm
	cfg.LibDefaults.DNSLookupKDC = false
	cfg.LibDefaults.DNSLookupRealm = false
	cfg.LibDefaults.Forwardable = false
	if tcp {
		cfg.LibDefaults.UDPPreferenceLimit = 1
	}
	cfg.Realms = []config.Realm{{Realm: testRealm, KDC: []string{addr}}}
	return client.NewWithPassword(user, testRealm, password, cfg, client.DisablePAFXFAST(true))
}

const alicePassword = "alice's test password"

// The daemon answers an AS-REQ from a gokrb5 client with a TGT, over UDP and
// over TCP; the refusals are the right ones.
func TestASREP(t *testing.T) {
	e := newEnv(t)
	d := e.start(e.spec())

	for _, tcp := range []bool{false, true} {
		name := map[bool]string{false: "udp", true: "tcp"}[tcp]
		t.Run(name+" alice gets a TGT", func(t *testing.T) {
			cl := krbClient(t, d.KDCAddr(), "alice", alicePassword, tcp)
			if err := cl.Login(); err != nil {
				t.Fatalf("AS exchange: %v", err)
			}
		})
		t.Run(name+" a wrong password is refused", func(t *testing.T) {
			cl := krbClient(t, d.KDCAddr(), "alice", "not her password", tcp)
			err := cl.Login()
			if err == nil {
				t.Fatal("a wrong password got a TGT")
			}
			if !strings.Contains(err.Error(), "PREAUTH_FAILED") {
				t.Fatalf("got %v, want KDC_ERR_PREAUTH_FAILED", err)
			}
		})
		t.Run(name+" a person with no password has no key", func(t *testing.T) {
			// carol is in the directory with no password_file: only the mint
			// listener can give her a TGT. An AS-REQ is refused, not answered
			// with a ticket nobody could have earned.
			cl := krbClient(t, d.KDCAddr(), "carol", "anything", tcp)
			err := cl.Login()
			if err == nil {
				t.Fatal("a person with no password got a TGT")
			}
			if !strings.Contains(err.Error(), "NULL_KEY") {
				t.Fatalf("got %v, want KDC_ERR_NULL_KEY", err)
			}
		})
		t.Run(name+" a stranger is refused", func(t *testing.T) {
			cl := krbClient(t, d.KDCAddr(), "mallory", "anything", tcp)
			if err := cl.Login(); err == nil {
				t.Fatal("an unknown principal got a TGT")
			}
		})
	}
}

// The KDC and the mint listener are two sockets, and the KDC's is loopback by
// default.
func TestListensOnTheLoopbackByDefault(t *testing.T) {
	e := newEnv(t)
	s := e.spec()
	s.Listen = `address = "127.0.0.1:0"`
	d := e.start(s)
	for _, a := range []string{d.KDCAddr(), d.MintAddr()} {
		host, _, _ := net.SplitHostPort(a)
		if !net.ParseIP(host).IsLoopback() {
			t.Errorf("listening on %s", a)
		}
	}
}

// mintClient dials the mint listener presenting cert (none when nil) and
// trusting the listener's CA.
func (e *env) mintClient(cert *tls.Certificate) *http.Client {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(e.ca.pem)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
}

func mintRequest(c *http.Client, addr, principal string) (*http.Response, error) {
	body, _ := json.Marshal(map[string]any{"principal": principal})
	req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/mint", bytes.NewReader(body))
	return c.Do(req)
}

func TestMintListener(t *testing.T) {
	e := newEnv(t)
	d := e.start(e.spec())
	addr := d.MintAddr()

	t.Run("a listed caller with a verified certificate gets a KRB-CRED", func(t *testing.T) {
		resp, err := mintRequest(e.mintClient(&e.goodCaller.pair), addr, "carol")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, b)
		}
		// [APPLICATION 22] KRB-CRED, RFC 4120 5.8.1. carol has no password:
		// this is the way she gets a TGT.
		if len(b) < 10 || b[0] != 0x76 {
			t.Fatalf("not a KRB-CRED: % x", b[:min(len(b), 16)])
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("Cache-Control %q", resp.Header.Get("Cache-Control"))
		}
	})

	t.Run("no client certificate: the handshake fails", func(t *testing.T) {
		if _, err := mintRequest(e.mintClient(nil), addr, "carol"); err == nil {
			t.Fatal("a caller with no certificate was served")
		}
	})

	t.Run("a certificate from another CA: the handshake fails", func(t *testing.T) {
		rogue := newCA(t, "rogue CA").issue(t, false, []string{testCaller}, time.Now().Add(time.Hour))
		if _, err := mintRequest(e.mintClient(&rogue.pair), addr, "carol"); err == nil {
			t.Fatal("a certificate no listed CA signed was accepted, with the right URI on it")
		}
	})

	t.Run("a verified certificate that is not on the list: 403", func(t *testing.T) {
		resp, err := mintRequest(e.mintClient(&e.otherCaller.pair), addr, "carol")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("a principal the directory does not hold: 403", func(t *testing.T) {
		resp, err := mintRequest(e.mintClient(&e.goodCaller.pair), addr, "mallory")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("nothing else is served", func(t *testing.T) {
		c := e.mintClient(&e.goodCaller.pair)
		resp, err := c.Get("https://" + addr + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("TLS 1.2 is refused", func(t *testing.T) {
		c := e.mintClient(&e.goodCaller.pair)
		c.Transport.(*http.Transport).TLSClientConfig.MinVersion = tls.VersionTLS12
		c.Transport.(*http.Transport).TLSClientConfig.MaxVersion = tls.VersionTLS12
		if _, err := mintRequest(c, addr, "carol"); err == nil {
			t.Fatal("TLS 1.2 was served")
		}
	})
}

// With no mint block there is no second listener at all.
func TestNoMintBlockNoMintListener(t *testing.T) {
	e := newEnv(t)
	s := e.spec()
	s.Mint = ""
	d := e.start(s)
	if a := d.MintAddr(); a != "" {
		t.Fatalf("a mint listener on %s", a)
	}
}

// Shutdown closes the sockets: the port is free again.
func TestShutdownFreesTheSockets(t *testing.T) {
	e := newEnv(t)
	rt, err := e.build(e.spec())
	if err != nil {
		t.Fatal(err)
	}
	d, err := Start(rt, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	addr, mint := d.KDCAddr(), d.MintAddr()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{addr, mint} {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			t.Fatalf("%s is still held: %v", a, err)
		}
		ln.Close()
	}
}

// Two listeners cannot take one address: Start says which, and frees the other.
func TestStartRefusesAnAddressInUse(t *testing.T) {
	e := newEnv(t)
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	s := e.spec()
	s.Listen = `address = "` + held.Addr().String() + `"`
	rt, err := e.build(s)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if _, err := Start(rt, t.Logf); err == nil || !strings.Contains(err.Error(), held.Addr().String()) {
		t.Fatalf("got %v", err)
	}
}
