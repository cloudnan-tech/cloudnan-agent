// Package database — lockfile_other.go.
//
// Fallback cross-process locking for non-Unix builds. Uses an O_CREATE|O_EXCL
// lockfile under <vault-dir>/.lock with bounded retries. The agent itself
// targets Linux, but keeping the package buildable on Windows lets `go test`
// and `go vet` run on developer machines without platform-specific gating
// of the vault tests.

//go:build !unix

package database

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	lockFileName       = ".lock"
	lockAcquireRetries = 600 // ~30s at 50ms intervals
	lockRetryInterval  = 50 * time.Millisecond
)

func (v *Vault) acquireFileLock() (func(), error) {
	lockPath := filepath.Join(v.dir, lockFileName)
	for i := 0; i < lockAcquireRetries; i++ {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			released := false
			return func() {
				if released {
					return
				}
				released = true
				_ = os.Remove(lockPath)
			}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("vault: acquire lockfile: %w", err)
		}
		time.Sleep(lockRetryInterval)
	}
	return nil, fmt.Errorf("vault: timed out acquiring lockfile %s", lockPath)
}
