// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

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
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", what, path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", what, path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s %s is not a regular file", what, path)
	}
	if runtime.GOOS != "windows" {
		if m := fi.Mode().Perm(); m&0o077 != 0 {
			return nil, fmt.Errorf("%s %s is mode %04o: group and others must not be able to read or write it (chmod 0600)", what, path, m)
		}
		if err := ownerOK(fi); err != nil {
			return nil, fmt.Errorf("%s %s: %w", what, path, err)
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSecret+1))
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", what, path, err)
	}
	if len(b) > maxSecret {
		return nil, fmt.Errorf("%s %s is larger than %d bytes", what, path, maxSecret)
	}
	return b, nil
}

// readKeytab reads and parses the keytab named by path, under readSecret's
// rules.
func readKeytab(path string) (*keytab.Keytab, error) {
	b, err := readSecret(path, "keytab")
	if err != nil {
		return nil, err
	}
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		return nil, fmt.Errorf("keytab %s: %w", path, err)
	}
	if len(kt.Entries) == 0 {
		return nil, fmt.Errorf("keytab %s: %w", path, errEmptyKeytab)
	}
	return kt, nil
}
