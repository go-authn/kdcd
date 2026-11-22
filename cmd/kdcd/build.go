// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/types"
)

// etypeAES256 is the one encryption type go-authn/kdc issues.
const etypeAES256 = 18

// Runtime is a configuration whose files have been read and whose directory
// has been opened: everything the daemon needs short of a socket.
type Runtime struct {
	Cfg    *Config
	Keytab *keytab.Keytab
	People directory.Source
	// TLS is the mint listener's configuration, nil without a mint block.
	TLS *tls.Config
}

// Build reads every secret the configuration names, under readSecret's rules,
// checks the keytab holds what the realm needs, and opens the directory. It
// listens on nothing, so `kdcd check` can run it on a machine where the daemon
// is already up.
func Build(cfg *Config) (*Runtime, error) {
	rt := &Runtime{Cfg: cfg}
	kt, err := readKeytab(cfg.KeytabFile)
	if err != nil {
		return nil, err
	}
	if err := checkKeytab(kt, cfg); err != nil {
		return nil, fmt.Errorf("keytab %s: %w", cfg.KeytabFile, err)
	}
	rt.Keytab = kt

	if cfg.Mint != nil {
		if rt.TLS, err = mintTLS(cfg.Mint); err != nil {
			return nil, err
		}
	}
	if rt.People, err = openPeople(cfg); err != nil {
		return nil, err
	}
	return rt, nil
}

// Close releases the directory.
func (r *Runtime) Close() error {
	if c, ok := r.People.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// checkKeytab asks the keytab what the library will ask it: the krbtgt key
// (the library refuses without it, but only with a message about the library)
// and the key of every service the operator said this realm serves.
func checkKeytab(kt *keytab.Keytab, cfg *Config) error {
	want := append([]string{"krbtgt/" + cfg.Realm}, cfg.Services...)
	for _, s := range want {
		p := types.PrincipalName{NameType: 2, NameString: strings.Split(s, "/")}
		if _, _, err := kt.GetEncryptionKey(p, cfg.Realm, 0, etypeAES256); err != nil {
			return fmt.Errorf("no aes256-cts-hmac-sha1-96 key for %s@%s (the only type this KDC issues): %w", s, cfg.Realm, err)
		}
	}
	return nil
}

// mintTLS builds the listener's TLS configuration: TLS 1.3, and a client
// certificate that must verify against the callers' CA. Without that the
// library's handler mints nothing, but this listener refuses the connection
// before a byte of HTTP is read.
func mintTLS(m *MintConfig) (*tls.Config, error) {
	certPEM, err := readPublic(m.CertFile, "mint cert_file")
	if err != nil {
		return nil, err
	}
	keyPEM, err := readSecret(m.KeyFile, "mint key_file")
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("mint cert_file and key_file: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("mint cert_file: %w", err)
	}
	if now := time.Now(); now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("mint cert_file is valid from %s to %s, and it is %s",
			leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	caPEM, err := readPublic(m.ClientCAFile, "mint client_ca_file")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("mint client_ca_file %s holds no certificate", m.ClientCAFile)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

// readPublic reads a file that holds no secret (a certificate), bounded.
func readPublic(path, what string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSecret+1))
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", what, path, err)
	}
	if len(b) > maxSecret {
		return nil, fmt.Errorf("%s %s is larger than %d bytes", what, path, maxSecret)
	}
	return b, nil
}

// afterDSNCheck runs between checking a DSN file and opening the directory
// with it; a test swaps the path there. Nothing else sets it.
var afterDSNCheck = func() {}

// openPeople opens the directory: the users blocks, then the user blocks, as
// one set. It closes what it opened when one fails.
func openPeople(cfg *Config) (directory.Source, error) {
	set := directory.NewSet()
	fail := func(err error) (directory.Source, error) {
		set.Close()
		return nil, err
	}
	for _, b := range cfg.Users {
		// hcldir reads the DSN by name; its permissions are checked here,
		// beforehand, by the rule every other secret meets, and it must carry
		// no password.
		if b.DSNFile != "" {
			what := fmt.Sprintf("users %q dsn_file", b.Kind)
			f, raw, err := openSecret(b.DSNFile, what)
			if err != nil {
				return fail(err)
			}
			if err := checkDSN(raw, what); err != nil {
				f.Close()
				return fail(err)
			}
			afterDSNCheck()
			// ⛔ Open the file that was checked, not its name: hcldir reads
			// the path it is given, and a path swapped since the check names
			// another file. /dev/fd/N reopens this very inode.
			// Rewound: on some systems /dev/fd/N is a dup that shares the
			// offset, and a read from the end sees an empty DSN.
			if p := fdPath(f); p != "" {
				if _, err := f.Seek(0, io.SeekStart); err != nil {
					f.Close()
					return fail(fmt.Errorf("%s: %w", what, err))
				}
				b.DSNFile = p
			}
			src, err := hcldir.Open(b)
			f.Close()
			if err != nil {
				return fail(fmt.Errorf("users %q: %w", b.Kind, err))
			}
			set.Add(src)
			continue
		}
		src, err := hcldir.Open(b)
		if err != nil {
			return fail(fmt.Errorf("users %q: %w", b.Kind, err))
		}
		set.Add(src)
	}
	if len(cfg.People) > 0 {
		var ub []hcldir.UserBlock
		for _, p := range cfg.People {
			ub = append(ub, hcldir.UserBlock{Name: p.Name})
		}
		src, err := hcldir.File(ub, nil)
		if err != nil {
			return fail(err)
		}
		set.Add(src)
	}
	return nameOnly{set}, nil
}

// nameOnly is the directory the KDC sees: who exists, and nothing that proves
// them. Whatever a source carried (a password, an NT hash, a key), the
// identities rebuilt here hold only the name, so the library can derive no
// long-term key and answers every AS-REQ for a person KDC_ERR_NULL_KEY. That is
// the structural half of "no password path"; the load-time refusals are the
// half that says why.
type nameOnly struct{ *directory.Set }

func (n nameOnly) Identities() ([]*directory.Identity, error) {
	ids, err := n.Set.Identities()
	if err != nil {
		return nil, err
	}
	out := make([]*directory.Identity, len(ids))
	for i, id := range ids {
		out[i] = directory.NewIdentity(id.Name())
	}
	return out, nil
}

// checkDSN refuses a connection string that carries a password: a database
// reached by a client certificate or a local socket needs none. Best effort on
// the three spellings the drivers take; nameOnly holds whatever it misses.
func checkDSN(raw []byte, what string) error {
	s := strings.TrimSpace(string(raw))
	if passwordWord.MatchString(s) {
		return fmt.Errorf("%s holds a password: %s", what, removedInV2)
	}
	if u, err := url.Parse(s); err == nil && u.User != nil {
		if _, has := u.User.Password(); has {
			return fmt.Errorf("%s holds a password: %s", what, removedInV2)
		}
	}
	if mysqlDSN.MatchString(s) {
		return fmt.Errorf("%s holds a password (user:password@): %s", what, removedInV2)
	}
	return nil
}

var mysqlDSN = regexp.MustCompile(`^[^:/@?\s]+:[^@\s]*@`)

// Summary describes what a configuration serves, for `kdcd check`. It prints
// names, types and versions, never a key.
func (r *Runtime) Summary() string {
	var b strings.Builder
	c := r.Cfg
	fmt.Fprintf(&b, "realm        %s\n", c.Realm)
	fmt.Fprintf(&b, "kdc          %s (tcp and udp)\n", c.KDCAddr)
	fmt.Fprintf(&b, "keytab       %s\n", c.KeytabFile)
	var ps []string
	for _, e := range r.Keytab.Entries {
		ps = append(ps, fmt.Sprintf("%s@%s kvno %d etype %d", strings.Join(e.Principal.Components, "/"), e.Principal.Realm, e.KVNO, e.Key.KeyType))
	}
	sort.Strings(ps)
	for _, p := range ps {
		fmt.Fprintf(&b, "  principal  %s\n", p)
	}
	fmt.Fprintf(&b, "directory    %s\n", r.People.Describe())
	if ids, err := r.People.Identities(); err != nil {
		fmt.Fprintf(&b, "  people     unreadable now: %v\n", err)
	} else {
		fmt.Fprintf(&b, "  people     %d\n", len(ids))
	}
	if m := c.Mint; m != nil {
		fmt.Fprintf(&b, "mint         https://%s/mint, mutual TLS (TLS 1.3)\n", m.Addr)
		for _, u := range m.Callers {
			fmt.Fprintf(&b, "  caller     %s\n", u)
		}
	} else {
		fmt.Fprintf(&b, "mint         off\n")
	}
	if k := c.KKDCP; k != nil {
		fmt.Fprintf(&b, "kkdcp        http://%s%s (MS-KKDCP, plain HTTP: TLS is the reverse proxy's)\n", k.Addr, k.Path)
	} else {
		fmt.Fprintf(&b, "kkdcp        off\n")
	}
	if c.Lifetime > 0 {
		fmt.Fprintf(&b, "lifetime     %v\n", c.Lifetime)
	}
	if c.MaxSkew > 0 {
		fmt.Fprintf(&b, "max_skew     %v\n", c.MaxSkew)
	}
	return b.String()
}
