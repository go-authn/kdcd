// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-authn/directory/hcldir"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// Defaults. The KDC listens on the loopback only: a realm's KDC is reached
// through an address somebody chose, never because nobody did.
const (
	defaultKDCAddr  = "127.0.0.1:88"
	defaultMintAddr = "127.0.0.1:8443"

	minLifetime = time.Minute
	maxLifetime = 24 * time.Hour
	maxSkewCap  = 15 * time.Minute

	maxConfig = 1 << 20
)

// The file's shape, decoded by gohcl. An argument the schema does not name is
// refused by the decoder, which is how `password = "..."` in a user block is
// impossible: secrets live in files, never in the configuration.
type fileConfig struct {
	Realm      string   `hcl:"realm"`
	KeytabFile string   `hcl:"keytab_file"`
	Services   []string `hcl:"services,optional"`
	Lifetime   string   `hcl:"lifetime,optional"`
	MaxSkew    string   `hcl:"max_skew,optional"`

	Listen *listenBlock `hcl:"listen,block"`
	Mint   *mintBlock   `hcl:"mint,block"`
	KKDCP  *kkdcpBlock  `hcl:"kkdcp,block"`

	// Directory blocks: where people come from (go-authn/directory/hcldir).
	Users  []hcldir.Block `hcl:"users,block"`
	People []userBlock    `hcl:"user,block"`
}

type listenBlock struct {
	Address       string `hcl:"address,optional"`
	AllowWildcard bool   `hcl:"allow_wildcard,optional"`
}

// A userBlock is somebody written in the configuration: a name, and nothing
// that proves them. A person gets a TGT only through the mint listener, from a
// caller that authenticated them (a passkey login at go-authn/bridge).
//
// PasswordFile is in the schema ONLY so that a configuration that still has it
// is refused with a message naming the removal, instead of the decoder's
// "unsupported argument". It is a pointer so that even `password_file = ""` is
// seen as written.
type userBlock struct {
	Name         string  `hcl:"name,label"`
	PasswordFile *string `hcl:"password_file,optional"`
}

// removedInV2 ends every refusal of a password path: there is none to enable.
const removedInV2 = "kdcd has no password path since v0.2.0 (removed, breaking): a person gets a TGT only through the mint listener, after a caller authenticated them with a passkey"

// kkdcpBlock turns on Kerberos over HTTPS (MS-KKDCP, go-authn/kdc's
// KKDCPHandler). The listener is PLAIN HTTP: TLS is a reverse proxy's job
// (Caddy), because Windows requires HTTPS and a certificate is renewed there,
// not here. Hence an address that names an interface, never a wildcard.
type kkdcpBlock struct {
	Listen string `hcl:"listen"`
	Path   string `hcl:"path,optional"`
}

// defaultKKDCPPath is where Windows' KdcProxy policy and MIT's krb5.conf
// examples point (`https://host/KdcProxy`).
const defaultKKDCPPath = "/KdcProxy"

type mintBlock struct {
	Address      string   `hcl:"address,optional"`
	CertFile     string   `hcl:"cert_file"`
	KeyFile      string   `hcl:"key_file"`
	ClientCAFile string   `hcl:"client_ca_file"`
	Callers      []string `hcl:"callers"`
}

// Config is a configuration that parsed and made sense. It names files; it has
// read none of the secrets (Build does).
type Config struct {
	Path       string
	Realm      string
	KeytabFile string
	Services   []string
	Lifetime   time.Duration // zero: the library's default, ten hours
	MaxSkew    time.Duration // zero: five minutes
	KDCAddr    string
	Mint       *MintConfig
	KKDCP      *KKDCPConfig
	Users      []hcldir.Block
	People     []userBlock
}

// KKDCPConfig is the optional MS-KKDCP listener (plain HTTP, behind a TLS proxy).
type KKDCPConfig struct {
	Addr string
	Path string
}

// MintConfig is the optional mint listener.
type MintConfig struct {
	Addr         string
	CertFile     string
	KeyFile      string
	ClientCAFile string
	Callers      []string
}

// realmRE is a realm as DNS writes it, in capitals (RFC 4120 6.1 recommends it,
// and a realm in lower case is nearly always a mistake that every client then
// has to be told about).
var realmRE = regexp.MustCompile(`^[A-Z0-9]([A-Z0-9.-]{0,253}[A-Z0-9])?$`)

// LoadConfig reads and checks the configuration file at path. It touches no
// secret and no network.
func LoadConfig(path string) (*Config, error) {
	src, err := readConfigFile(path)
	if err != nil {
		return nil, err
	}
	f, diags := hclparse.NewParser().ParseHCL(src, path)
	if diags.HasErrors() {
		return nil, fmt.Errorf("%s", diags.Error())
	}
	var fc fileConfig
	if diags := gohcl.DecodeBody(f.Body, nil, &fc); diags.HasErrors() {
		return nil, fmt.Errorf("%s", diags.Error())
	}
	c, err := fc.resolve()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.Path = path
	return c, nil
}

// readConfigFile opens the file once. The configuration decides who may ask
// for tickets, so a file that group or others can write is refused: whoever
// writes it chooses the mint callers.
func readConfigFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if runtime.GOOS != "windows" {
		if m := fi.Mode().Perm(); m&0o022 != 0 {
			return nil, fmt.Errorf("%s is mode %04o: group and others must not be able to write it (chmod 0640 or 0600)", path, m)
		}
		// The mode is the owner's to change: a file owned by another account
		// is one that account can make writable again after this check.
		if err := ownerOK(fi); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, maxConfig+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxConfig {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxConfig)
	}
	return b, nil
}

func (fc *fileConfig) resolve() (*Config, error) {
	c := &Config{Realm: fc.Realm, KeytabFile: fc.KeytabFile, Services: fc.Services,
		Users: fc.Users, People: fc.People}
	if !realmRE.MatchString(c.Realm) {
		return nil, fmt.Errorf("realm %q: a realm is a DNS name in capitals, such as EXAMPLE.ORG", c.Realm)
	}
	if c.KeytabFile == "" {
		return nil, fmt.Errorf("keytab_file is empty: the keytab holds krbtgt/%s@%s, which signs every ticket", c.Realm, c.Realm)
	}
	seen := map[string]bool{}
	for _, s := range c.Services {
		if err := checkServiceName(s); err != nil {
			return nil, fmt.Errorf("services: %w", err)
		}
		if seen[s] {
			return nil, fmt.Errorf("services: %q is listed twice", s)
		}
		seen[s] = true
	}
	var err error
	if c.Lifetime, err = parseDuration("lifetime", fc.Lifetime, minLifetime, maxLifetime); err != nil {
		return nil, err
	}
	if c.MaxSkew, err = parseDuration("max_skew", fc.MaxSkew, time.Second, maxSkewCap); err != nil {
		return nil, err
	}

	addr, wild := defaultKDCAddr, false
	if fc.Listen != nil {
		if fc.Listen.Address != "" {
			addr = fc.Listen.Address
		}
		wild = fc.Listen.AllowWildcard
	}
	if c.KDCAddr, err = checkListen("listen address", addr, wild); err != nil {
		return nil, err
	}

	if m := fc.Mint; m != nil {
		mc := &MintConfig{Addr: defaultMintAddr, CertFile: m.CertFile, KeyFile: m.KeyFile,
			ClientCAFile: m.ClientCAFile, Callers: m.Callers}
		if m.Address != "" {
			mc.Addr = m.Address
		}
		// ⛔ Never a wildcard: the mint listener hands out TGTs and belongs on
		// an internal interface, named.
		if mc.Addr, err = checkListen("mint address", mc.Addr, false); err != nil {
			return nil, err
		}
		for name, v := range map[string]string{"cert_file": mc.CertFile, "key_file": mc.KeyFile, "client_ca_file": mc.ClientCAFile} {
			if v == "" {
				return nil, fmt.Errorf("mint: %s is empty: the mint listener is mutual TLS and has no plain mode", name)
			}
		}
		if len(mc.Callers) == 0 {
			// The library reads an empty list as "minting off"; a mint block
			// that mints nothing is a mistake worth naming.
			return nil, fmt.Errorf("mint: callers is empty: name the URI subjectAltName of each client certificate allowed to ask, or delete the block")
		}
		seen := map[string]bool{}
		for _, u := range mc.Callers {
			if err := checkCaller(u); err != nil {
				return nil, fmt.Errorf("mint: callers: %w", err)
			}
			if seen[u] {
				return nil, fmt.Errorf("mint: callers: %q is listed twice", u)
			}
			seen[u] = true
		}
		c.Mint = mc
	}

	if k := fc.KKDCP; k != nil {
		kc := &KKDCPConfig{Path: defaultKKDCPPath}
		if kc.Addr, err = checkListen("kkdcp listen", k.Listen, false); err != nil {
			return nil, err
		}
		if k.Path != "" {
			kc.Path = k.Path
		}
		if err := checkKKDCPPath(kc.Path); err != nil {
			return nil, fmt.Errorf("kkdcp: path: %w", err)
		}
		// Port 0 is "any free port": two of them never collide.
		if !strings.HasSuffix(kc.Addr, ":0") && (kc.Addr == c.KDCAddr || (c.Mint != nil && kc.Addr == c.Mint.Addr)) {
			return nil, fmt.Errorf("kkdcp listen %s is the address of another listener", kc.Addr)
		}
		c.KKDCP = kc
	}

	if len(c.Users) == 0 && len(c.People) == 0 {
		return nil, fmt.Errorf("no directory: write a users \"sql\" or users \"ldap\" block, or user blocks")
	}
	names := map[string]bool{}
	for _, p := range c.People {
		if p.Name == "" {
			return nil, fmt.Errorf("a user block has no name")
		}
		if names[p.Name] {
			return nil, fmt.Errorf("user %q is declared twice", p.Name)
		}
		names[p.Name] = true
		if p.PasswordFile != nil {
			return nil, fmt.Errorf("user %q: password_file: %s", p.Name, removedInV2)
		}
	}
	for _, b := range c.Users {
		if err := checkNoPassword(b); err != nil {
			return nil, fmt.Errorf("users %q: %w", b.Kind, err)
		}
		if err := b.Check(); err != nil {
			return nil, fmt.Errorf("users %q: %w", b.Kind, err)
		}
	}
	return c, nil
}

// passwordWord finds a column or attribute named like a secret that proves a
// person. It is a refusal at load, for the message; the guarantee that no
// password reaches the KDC is structural (see nameOnly), whatever this misses.
var passwordWord = regexp.MustCompile(`(?i)\b(user_?password|password|passwd|pwd|nt_?hash|password_?hash|passhash)\b`)

// checkNoPassword refuses a directory block that is written to carry, or to
// reach the directory with, a password.
func checkNoPassword(b hcldir.Block) error {
	if b.BindPasswordFile != "" {
		return fmt.Errorf("bind_password_file: %s", removedInV2)
	}
	if b.BindDN != "" {
		return fmt.Errorf("bind_dn: a simple bind proves itself with a password: %s. An ldap source is read anonymously (hcldir has no client-certificate or SASL EXTERNAL bind yet)", removedInV2)
	}
	for name, q := range map[string]string{"users": b.UsersQuery, "users_attributes": b.UsersAttributesQuery,
		"groups": b.GroupsQuery, "groups_attributes": b.GroupsAttributesQuery} {
		if m := passwordWord.FindString(q); m != "" {
			return fmt.Errorf("%s names a %q column: %s. A directory says who exists and their groups, nothing that proves them", name, m, removedInV2)
		}
	}
	for _, a := range append(append([]string(nil), b.Attributes...), b.GroupAttributes...) {
		if m := passwordWord.FindString(a); m != "" {
			return fmt.Errorf("attributes names %q: %s", m, removedInV2)
		}
	}
	return nil
}

func parseDuration(name, v string, lo, hi time.Duration) (time.Duration, error) {
	if v == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s %q: %w", name, v, err)
	}
	if d < lo || d > hi {
		return 0, fmt.Errorf("%s %v: between %v and %v", name, d, lo, hi)
	}
	return d, nil
}

// checkListen validates host:port. The host is an IP literal, never a name: a
// name resolves to whatever DNS says at start, and an address that is not the
// one the operator read is how a KDC ends up on an interface nobody chose.
// The unspecified address (0.0.0.0, ::) needs allow = true.
func checkListen(what, addr string, allowWildcard bool) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("%s %q: %w (write IP:port, such as 127.0.0.1:88)", what, addr, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", fmt.Errorf("%s %q: the host must be an IP address, not a name", what, addr)
	}
	if ip.Zone() != "" {
		return "", fmt.Errorf("%s %q: a zone is not supported", what, addr)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", fmt.Errorf("%s %q: the port is a number from 0 to 65535", what, addr)
	}
	if ip.IsUnspecified() && !allowWildcard {
		if what == "mint address" {
			return "", fmt.Errorf("%s %q is the wildcard: the mint listener hands out TGTs, name its interface", what, addr)
		}
		return "", fmt.Errorf("%s %q is the wildcard, which serves every interface: name one, or set allow_wildcard = true in listen", what, addr)
	}
	return net.JoinHostPort(ip.String(), strconv.FormatUint(n, 10)), nil
}

// checkKKDCPPath accepts an absolute URL path of plain characters: it is
// matched exactly by the mux, and a path with a pattern's syntax ("{x}", a
// host, a trailing slash that makes it a subtree) would serve more than named.
func checkKKDCPPath(p string) error {
	if len(p) < 2 || p[0] != '/' || strings.HasSuffix(p, "/") {
		return fmt.Errorf("%q: write an absolute path without a trailing slash, such as /KdcProxy", p)
	}
	for _, r := range p {
		ok := r == '/' || r == '-' || r == '_' || r == '.' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok || strings.Contains(p, "//") || strings.Contains(p, "..") {
			return fmt.Errorf("%q: letters, digits and - _ . / only, no empty or .. segment", p)
		}
	}
	return nil
}

// checkServiceName accepts service/host, no realm, no further slash.
func checkServiceName(s string) error {
	svc, host, ok := strings.Cut(s, "/")
	if !ok || svc == "" || host == "" || strings.ContainsAny(s, "@\\ \t\n,\"") || strings.Contains(host, "/") {
		return fmt.Errorf("%q: write service/host, such as cifs/fs.example.org", s)
	}
	if svc == "krbtgt" {
		return fmt.Errorf("%q: krbtgt is the realm's own key and is checked already", s)
	}
	return nil
}

// checkCaller accepts the URI the library will compare to a certificate's
// subjectAltName byte for byte (x509.Certificate.URIs, u.String()).
func checkCaller(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" || u.String() != s {
		return fmt.Errorf("%q is not an absolute URI in the form a certificate carries (such as https://login.example.org)", s)
	}
	if strings.ContainsAny(s, "*") {
		return fmt.Errorf("%q holds a wildcard: callers are matched exactly", s)
	}
	return nil
}
