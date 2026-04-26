// Package database — vault_other.go.
//
// Non-Unix owner check fallback. The agent targets Linux but the package
// must build on Windows so developers can `go vet` and unit-test on any
// host. On non-Unix platforms ownership is reported as "match by default";
// this is acceptable because the vault is never deployed in production
// on Windows — the binary is Linux-only at install time.

//go:build !unix

package database

import "os"

func auditOwner(path string, st os.FileInfo) error {
	_ = path
	_ = st
	return nil
}
