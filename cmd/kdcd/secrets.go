// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/go-authn/secretsource"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// maxSecret bounds what is read from a secret file: a keytab is a few entries
// of a few hundred bytes, a key or a password one line. A path that points at
// something huge is a mistake, not a secret.
const maxSecret = 1 << 20

// errEmptyKeytab is a keytab that parses and holds nothing.
var errEmptyKeytab = errors.New("it holds no key")

// readSecret opens path ONCE, checks the open file, and returns what was read
// from it. Checking the path and then reading the path again would check one
// file and read whatever stands there a moment later (the model is
// go-fileshare/fileshare v0.50.0, readKeytab).
//
// On Unix the file must be a regular file that group and others cannot read or
// write (mode 0600 or 0400), and must belong to root or to the account this
// daemon runs as: a key another account can read is a key that account holds,
// and an owner other than those can rewrite the mode. Windows has no mode bits
// worth reading, so only the reading is done there; its ACLs are the
// operator's (the README says where to put the files).
//
// ⛔ Stricter than fileshare's: group-READ is refused too. The unit runs the
// daemon as its own user and the files belong to it (or to root, who is not
// bound by the mode), so no group needs to read them.
func readSecret(path, what string) ([]byte, error) {
	f, b, err := openSecret(path, what)
	if err != nil {
		return nil, err
	}
	f.Close()
	return b, nil
}

// openSecret is readSecret that keeps the checked file open, for a caller
// that must hand a library the SAME file it checked and not its name.
func openSecret(path, what string) (*os.File, []byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s: %w", what, path, err)
	}
	fail := func(err error) (*os.File, []byte, error) {
		f.Close()
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		return fail(fmt.Errorf("%s %s: %w", what, path, err))
	}
	if !fi.Mode().IsRegular() {
		return fail(fmt.Errorf("%s %s is not a regular file", what, path))
	}
	if runtime.GOOS != "windows" {
		if m := fi.Mode().Perm(); m&0o077 != 0 {
			return fail(fmt.Errorf("%s %s is mode %04o: group and others must not be able to read or write it (chmod 0600)", what, path, m))
		}
		if err := ownerOK(fi); err != nil {
			return fail(fmt.Errorf("%s %s: %w", what, path, err))
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSecret+1))
	if err != nil {
		return fail(fmt.Errorf("%s %s: %w", what, path, err))
	}
	if len(b) > maxSecret {
		return fail(fmt.Errorf("%s %s is larger than %d bytes", what, path, maxSecret))
	}
	return f, b, nil
}

// readKeytab reads and parses the keytab named by path, under readSecret's
// rules.
func readKeytab(path string) (*keytab.Keytab, error) {
	b, err := readSecret(path, "keytab")
	if err != nil {
		return nil, err
	}
	return parseKeytab(b, path)
}

func parseKeytab(b []byte, where string) (*keytab.Keytab, error) {
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		return nil, fmt.Errorf("keytab %s: %w", where, err)
	}
	if len(kt.Entries) == 0 {
		return nil, fmt.Errorf("keytab %s: %w", where, errEmptyKeytab)
	}
	return kt, nil
}

// keyMaterial is where a piece of key material comes from: a file named by
// `<name>_file` (read by readSecret, byte for byte, up to maxSecret) or a
// secretsource reference named by `<name>_from`. Exactly one is set.
type keyMaterial struct {
	File string
	From string
}

// where names the source for a message, never the secret.
func (k keyMaterial) where() string {
	if k.From != "" {
		return k.From
	}
	return k.File
}

// checkKeyMaterial refuses none or both of `<name>_file` and `<name>_from`, and
// a `_from` that is a file: reference.
//
// ⛔ `file:` is refused in `_from`: secretsource strips one trailing newline
// from a file, which changes a binary keytab whose last byte is 0x0a, and
// readSecret is the stricter reader (owner, no group access, up to maxSecret).
// A path is written `<name>_file`. `systemd-creds:` returns the exact bytes.
func checkKeyMaterial(name string, k keyMaterial) error {
	switch {
	case k.File != "" && k.From != "":
		return fmt.Errorf("%s_file and %s_from are both set: name one source of the secret", name, name)
	case k.File == "" && k.From == "":
		return fmt.Errorf("%s_file is empty: name the file, or give %s_from a secretsource reference (systemd-creds:NAME)", name, name)
	}
	if strings.HasPrefix(k.From, "file:") {
		return fmt.Errorf("%s_from: a file: reference is not accepted (it strips a trailing newline, which alters binary key material); write the path as %s_file", name, name)
	}
	if k.From != "" {
		if _, err := secretsource.Parse(k.From); err != nil {
			return fmt.Errorf("%s_from: %w", name, err)
		}
	}
	return nil
}

// readKeyMaterial returns the bytes the source holds.
func readKeyMaterial(k keyMaterial, what string) ([]byte, error) {
	if k.From == "" {
		return readSecret(k.File, what)
	}
	ctx, cancel := context.WithTimeout(context.Background(), secretsource.Timeout)
	defer cancel()
	s, err := secretsource.Open(ctx, k.From)
	if err != nil {
		return nil, fmt.Errorf("%s_from %s: %w", what, k.From, err)
	}
	defer s.Close()
	// Copy: Close wipes the secret's own buffer.
	return append([]byte(nil), s.Bytes()...), nil
}
