// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package main

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// euid is the account this daemon runs as; a variable so that a test can say
// it is somebody else.
var euid = os.Geteuid

// ownerOK accepts a file owned by root or by the account this daemon runs as.
func ownerOK(fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("its owner cannot be read")
	}
	if uid := int(st.Uid); uid != 0 && uid != euid() {
		return fmt.Errorf("it belongs to uid %d, neither root nor this daemon (uid %d)", uid, euid())
	}
	return nil
}
