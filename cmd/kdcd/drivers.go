// SPDX-License-Identifier: BSD-3-Clause

package main

// The database drivers a `users "sql"` block can name. hcldir does not import
// them (a deployment chooses), so the program does: all three are pure Go, and
// the build stays CGO_ENABLED=0.
import (
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)
