// Package database — lockfile_unix.go.
//
// Cross-process exclusive locking for vault read-modify-write sequences on
// Unix systems (Linux, macOS, BSD). Uses flock(LOCK_EX) on the encrypted
// vault blob file. The blob file is created lazily; if it does not yet
// exist we open it with O_CREATE|os.O_RDWR and zero-byte size so flock has
// a valid file descriptor to lock against, then leave it empty for the
// caller's writeAll to populate.

//go:build unix

package database

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// acquireFileLock takes an exclusive (LOCK_EX) flock on the blob file and
// returns an unlock function the caller must invoke. The returned function
// is safe to call exactly once.
func (v *Vault) acquireFileLock() (func(), error) {
	// Open the blob with O_CREATE so we always have something to flock.
	// O_RDWR (not O_RDONLY) so the same descriptor would be writable if
	// callers chose to write through it; we still use atomic-rename writes.
	f, err := os.OpenFile(v.blobPath, os.O_RDWR|os.O_CREATE, vaultBlobPerm)
	if err != nil {
		return nil, fmt.Errorf("vault: open blob for lock: %w", err)
	}
	// If we just created the file, ensure perms are exactly 0600 — umask may
	// have widened them.
	if err := os.Chmod(v.blobPath, vaultBlobPerm); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("vault: chmod blob: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("vault: flock: %w", err)
	}
	unlocked := false
	return func() {
		if unlocked {
			return
		}
		unlocked = true
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
