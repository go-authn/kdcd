// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package main

import (
	"os"
	"strconv"
)

// fdPath names an open file by its descriptor, so that opening the name opens
// the same inode however the path it was first opened by is changed after.
// Linux, macOS and the BSDs all have /dev/fd.
func fdPath(f *os.File) string {
	return "/dev/fd/" + strconv.Itoa(int(f.Fd()))
}
