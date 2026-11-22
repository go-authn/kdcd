// SPDX-License-Identifier: BSD-3-Clause

package main

import "os"

// fdPath is empty on Windows, which has no descriptor namespace; the name is
// used there, as before.
func fdPath(*os.File) string { return "" }
