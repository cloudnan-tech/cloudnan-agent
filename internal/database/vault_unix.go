// Package database — vault_unix.go.
//
// Unix-specific owner verification for the credential vault. Reads the
// file's owning UID via syscall.Stat_t and compares it to the agent's
// effective UID. The vault refuses to operate on files owned by a
// different user — symptoms of this would be a sudo'd `cp`, a misconfigured
// init script, or an attacker swapping in their own creds.

//go:build unix

package database

import (
	"fmt"
	"os"
	"syscall"
)

func auditOwner(path string, st os.FileInfo) error {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("vault: cannot determine owner of %s on this platform", path)
	}
	if uint32(os.Geteuid()) != sys.Uid {
		return fmt.Errorf("vault: refusing to operate: %s owned by uid %d, agent uid is %d", path, sys.Uid, os.Geteuid())
	}
	return nil
}
