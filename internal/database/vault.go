// Package database — vault.go.
//
// This file implements the agent-local encrypted credential vault for database
// connections. The vault is the security boundary for DB credentials managed
// by Cloudnan: keys never leave the host. The encrypted blob is stored at rest
// with permissions 0600; the symmetric key is stored at rest with permissions
// 0400. Both files must be owned by the agent's effective UID; the vault
// refuses to operate if any of these invariants are violated.
//
// On-disk layout (under CLOUDNAN_VAULT_DIR or /var/lib/cloudnan-agent):
//
//	db-vault.enc   — AES-256-GCM(nonce || ciphertext) over a JSON map[string]CredEntry
//	db-vault.key   — exactly 32 raw bytes of key material (mode 0400)
//	.lock          — fallback advisory lock file (used if flock is unavailable)
//
// All read-modify-write sequences are serialized with flock(LOCK_EX) on the
// encrypted blob (POSIX/Unix); on platforms where flock is unavailable a
// lockfile-based fallback is used (see lockfile.go and lockfile_unix.go).
package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	vaultDirEnv     = "CLOUDNAN_VAULT_DIR"
	defaultVaultDir = "/var/lib/cloudnan-agent"
	vaultBlobName   = "db-vault.enc"
	vaultKeyName    = "db-vault.key"
	vaultDirPerm    = 0o700
	vaultBlobPerm   = 0o600
	vaultKeyPerm    = 0o400
	keySize         = 32 // AES-256
	gcmNonceSize    = 12
)

// CredEntry is the persisted record for a single database instance. The
// instance_id (the map key on disk) is not duplicated here.
type CredEntry struct {
	Engine        string    `json:"engine"` // "mysql" | "mariadb" | "postgresql"
	Host          string    `json:"host"`
	Port          uint32    `json:"port"`
	SocketPath    string    `json:"socket_path,omitempty"`
	Username      string    `json:"username"`
	Password      string    `json:"password"`
	UseTLS        bool      `json:"use_tls"`
	TLSCAPem      string    `json:"tls_ca_pem,omitempty"`
	DiscoveryHint string    `json:"discovery_hint,omitempty"`
	ConnectedAt   time.Time `json:"connected_at"`
}

// Vault is the encrypted credential store. A single Vault instance is safe
// for concurrent use from goroutines within one process; cross-process
// safety is provided by an exclusive file lock on the blob file.
type Vault struct {
	dir      string
	blobPath string
	keyPath  string
	mu       sync.Mutex // serializes in-process access
}

// OpenVault prepares the vault directory, ensures the key file exists with
// correct permissions, and verifies that any existing blob is openable.
// It does not load the blob into memory until a Get/Put/Delete/List call.
func OpenVault() (*Vault, error) {
	dir := os.Getenv(vaultDirEnv)
	if dir == "" {
		dir = defaultVaultDir
	}
	if err := ensureVaultDir(dir); err != nil {
		return nil, err
	}
	v := &Vault{
		dir:      dir,
		blobPath: filepath.Join(dir, vaultBlobName),
		keyPath:  filepath.Join(dir, vaultKeyName),
	}
	if _, err := v.loadOrCreateKey(); err != nil {
		return nil, fmt.Errorf("vault: prepare key: %w", err)
	}
	// Permission audit on the blob file if it exists. Non-existence is fine.
	if _, err := os.Stat(v.blobPath); err == nil {
		if err := auditFilePerms(v.blobPath, vaultBlobPerm); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("vault: stat blob: %w", err)
	}
	return v, nil
}

// Get returns the credential entry for instance_id. Returns os.ErrNotExist
// if no entry is present.
func (v *Vault) Get(instanceID string) (*CredEntry, error) {
	if instanceID == "" {
		return nil, errors.New("vault: empty instance_id")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	unlock, err := v.acquireFileLock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	entries, err := v.readAll()
	if err != nil {
		return nil, err
	}
	entry, ok := entries[instanceID]
	if !ok {
		return nil, os.ErrNotExist
	}
	return entry, nil
}

// Put inserts or replaces the credential entry for instance_id.
func (v *Vault) Put(instanceID string, entry *CredEntry) error {
	if instanceID == "" {
		return errors.New("vault: empty instance_id")
	}
	if entry == nil {
		return errors.New("vault: nil entry")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	unlock, err := v.acquireFileLock()
	if err != nil {
		return err
	}
	defer unlock()

	entries, err := v.readAll()
	if err != nil {
		return err
	}
	cp := *entry
	if cp.ConnectedAt.IsZero() {
		cp.ConnectedAt = time.Now().UTC()
	}
	entries[instanceID] = &cp
	return v.writeAll(entries)
}

// Delete removes the entry for instance_id. Returns nil if the entry was
// absent (idempotent delete).
func (v *Vault) Delete(instanceID string) error {
	if instanceID == "" {
		return errors.New("vault: empty instance_id")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	unlock, err := v.acquireFileLock()
	if err != nil {
		return err
	}
	defer unlock()

	entries, err := v.readAll()
	if err != nil {
		return err
	}
	if _, ok := entries[instanceID]; !ok {
		return nil
	}
	delete(entries, instanceID)
	return v.writeAll(entries)
}

// List returns all known instance IDs. Credentials are deliberately not
// returned by this call — listing must never expose secret material.
func (v *Vault) List() ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	unlock, err := v.acquireFileLock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	entries, err := v.readAll()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	return ids, nil
}

// ----- internals -----

// ensureVaultDir creates dir with mode 0700 if missing, otherwise verifies
// that an existing directory is at least owned by the current user.
func ensureVaultDir(dir string) error {
	st, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, vaultDirPerm); err != nil {
			return fmt.Errorf("vault: create dir %s: %w", dir, err)
		}
		// MkdirAll honors umask; force the desired perms explicitly.
		if err := os.Chmod(dir, vaultDirPerm); err != nil {
			return fmt.Errorf("vault: chmod dir %s: %w", dir, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("vault: stat dir %s: %w", dir, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("vault: %s exists but is not a directory", dir)
	}
	if err := auditOwner(dir, st); err != nil {
		return err
	}
	return nil
}

// loadOrCreateKey reads the key file, generating it on first use. Returns
// the 32-byte key. Performs permission audit on the key file every call.
func (v *Vault) loadOrCreateKey() ([]byte, error) {
	st, err := os.Stat(v.keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key := make([]byte, keySize)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, fmt.Errorf("vault: read random key: %w", err)
		}
		// Write atomically: O_CREATE|O_EXCL with restrictive perms.
		f, err := os.OpenFile(v.keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, vaultKeyPerm)
		if err != nil {
			// If a parallel agent created it between Stat and Open, fall through to read.
			if errors.Is(err, os.ErrExist) {
				return v.loadKey()
			}
			return nil, fmt.Errorf("vault: create key file: %w", err)
		}
		if _, err := f.Write(key); err != nil {
			_ = f.Close()
			_ = os.Remove(v.keyPath)
			return nil, fmt.Errorf("vault: write key: %w", err)
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("vault: close key: %w", err)
		}
		// Re-chmod in case umask widened the bits.
		if err := os.Chmod(v.keyPath, vaultKeyPerm); err != nil {
			return nil, fmt.Errorf("vault: chmod key: %w", err)
		}
		return key, nil
	}
	if err != nil {
		return nil, fmt.Errorf("vault: stat key: %w", err)
	}
	if st.Size() != keySize {
		return nil, fmt.Errorf("vault: key file %s has wrong size %d (want %d)", v.keyPath, st.Size(), keySize)
	}
	if err := auditFilePerms(v.keyPath, vaultKeyPerm); err != nil {
		return nil, err
	}
	return v.loadKey()
}

func (v *Vault) loadKey() ([]byte, error) {
	if err := auditFilePerms(v.keyPath, vaultKeyPerm); err != nil {
		return nil, err
	}
	key, err := os.ReadFile(v.keyPath)
	if err != nil {
		return nil, fmt.Errorf("vault: read key: %w", err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("vault: key file has wrong length %d", len(key))
	}
	return key, nil
}

// readAll decrypts and returns all entries. If the blob does not yet exist,
// returns an empty map.
func (v *Vault) readAll() (map[string]*CredEntry, error) {
	key, err := v.loadKey()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(v.blobPath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]*CredEntry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("vault: read blob: %w", err)
	}
	if err := auditFilePerms(v.blobPath, vaultBlobPerm); err != nil {
		return nil, err
	}
	// The lockfile path opens the blob with O_CREATE on first use so flock has
	// a valid descriptor to lock against, leaving an empty file behind. Treat
	// "exists but empty" the same as "doesn't exist yet" — first writeAll will
	// populate it. Any non-empty file shorter than nonce+tag is real corruption
	// and falls through to the decrypt error path.
	if len(data) == 0 {
		return map[string]*CredEntry{}, nil
	}
	plain, err := decrypt(key, data)
	if err != nil {
		return nil, fmt.Errorf("vault: decrypt: %w", err)
	}
	if len(plain) == 0 {
		return map[string]*CredEntry{}, nil
	}
	entries := map[string]*CredEntry{}
	if err := json.Unmarshal(plain, &entries); err != nil {
		return nil, fmt.Errorf("vault: unmarshal: %w", err)
	}
	return entries, nil
}

// writeAll encrypts and atomically replaces the blob file.
func (v *Vault) writeAll(entries map[string]*CredEntry) error {
	key, err := v.loadKey()
	if err != nil {
		return err
	}
	plain, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("vault: marshal: %w", err)
	}
	ct, err := encrypt(key, plain)
	if err != nil {
		return fmt.Errorf("vault: encrypt: %w", err)
	}
	tmp, err := os.CreateTemp(v.dir, "db-vault.enc.tmp.*")
	if err != nil {
		return fmt.Errorf("vault: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best-effort cleanup if rename fails.
		if _, err := os.Stat(tmpName); err == nil {
			_ = os.Remove(tmpName)
		}
	}()
	if err := os.Chmod(tmpName, vaultBlobPerm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("vault: chmod temp: %w", err)
	}
	if _, err := tmp.Write(ct); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("vault: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("vault: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("vault: close temp: %w", err)
	}
	if err := os.Rename(tmpName, v.blobPath); err != nil {
		return fmt.Errorf("vault: rename temp: %w", err)
	}
	return nil
}

// encrypt produces nonce || ciphertext using AES-256-GCM.
func encrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// decrypt expects nonce || ciphertext as produced by encrypt.
func decrypt(key, blob []byte) ([]byte, error) {
	if len(blob) < gcmNonceSize+1 {
		return nil, errors.New("ciphertext too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if gcm.NonceSize() != gcmNonceSize {
		return nil, fmt.Errorf("unexpected GCM nonce size %d", gcm.NonceSize())
	}
	nonce := blob[:gcmNonceSize]
	ct := blob[gcmNonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

// auditFilePerms enforces that path has exactly the expected mode bits and
// that its owner UID matches the agent's effective UID. Refuses to operate
// on any deviation — this is the highest-trust component on the host.
func auditFilePerms(path string, want os.FileMode) error {
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("vault: stat %s: %w", path, err)
	}
	got := st.Mode().Perm()
	if got != want {
		return fmt.Errorf("vault: refusing to operate: %s has mode %#o, want %#o", path, got, want)
	}
	return auditOwner(path, st)
}

// auditOwner verifies the file is owned by the current effective UID.
// Implemented in vault_unix.go and vault_other.go for platform isolation.
