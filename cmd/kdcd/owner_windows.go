// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package main

import "io/fs"

// euid exists so that the tests build on Windows; nothing reads it there.
var euid = func() int { return -1 }

// ownerOK has nothing to say on Windows: readSecret does not call it there.
func ownerOK(fs.FileInfo) error { return nil }
