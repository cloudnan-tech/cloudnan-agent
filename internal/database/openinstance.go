// Package database — openinstance.go.
//
// Canonical helpers for opening a *sql.DB to a managed instance from
// vault-stored credentials. openInstance opens to the engine's default
// administrative database (mysql/mariadb need none specified;
// postgres uses /postgres). openInstanceForDatabase targets a specific
// user database — required for postgres, where the database to query
// is selected at connection time, and convenient for mysql where it
// runs `USE <name>` on the freshly-opened pool.
//
// Both helpers consult the encrypted vault for credentials, refuse to
// open if the engine recorded at connect time is not one we support,
// and tear the pool back down on any error along the way so callers do
// not need to track partially-initialized state.
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	pb "github.com/cloudnan-tech/cloudnan-agent/proto/agent"
)

// openInstance is the canonical setup path used by every per-instance op.
// It resolves credentials from the vault, picks the right driver, opens
// a pool, and returns the driver + *sql.DB + the original CredEntry. The
// caller is responsible for db.Close(). On any error along the way the
// pool (if opened) is closed before returning.
func (h *Handler) openInstance(ctx context.Context, instanceID string) (Driver, *sql.DB, *CredEntry, error) {
	driver, entry, conn, err := h.resolveInstance(instanceID)
	if err != nil {
		return nil, nil, nil, err
	}
	db, err := driver.Open(ctx, conn, entry.Username, entry.Password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open: %w", err)
	}
	return driver, db, entry, nil
}

// openInstanceForDatabase opens a pool targeting dbName specifically:
//
//   - PostgreSQL: dbName is encoded into the DSN at Open time, because
//     pq selects the database at connection establishment and cannot be
//     redirected with USE.
//   - MySQL/MariaDB: dbName is selected with `USE <quoted>` immediately
//     after Open. The pool keeps the selection for every connection it
//     hands out, since SetMaxIdleConns(1) limits us to a single physical
//     conn under typical agent usage.
//
// dbName == "" falls back to openInstance.
func (h *Handler) openInstanceForDatabase(ctx context.Context, instanceID, dbName string) (Driver, *sql.DB, *CredEntry, error) {
	if dbName == "" {
		return h.openInstance(ctx, instanceID)
	}
	driver, entry, conn, err := h.resolveInstance(instanceID)
	if err != nil {
		return nil, nil, nil, err
	}

	switch driver.Engine() {
	case pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL:
		db, err := openPostgresWithDatabase(ctx, conn, entry.Username, entry.Password, dbName)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("open: %w", err)
		}
		return driver, db, entry, nil
	case pb.DatabaseEngine_DATABASE_ENGINE_MYSQL,
		pb.DatabaseEngine_DATABASE_ENGINE_MARIADB:
		db, err := driver.Open(ctx, conn, entry.Username, entry.Password)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("open: %w", err)
		}
		if _, err := db.ExecContext(ctx, "USE "+quoteMySQLIdent(dbName)); err != nil {
			_ = db.Close()
			return nil, nil, nil, fmt.Errorf("use %s: %w", dbName, err)
		}
		return driver, db, entry, nil
	default:
		return nil, nil, nil, fmt.Errorf("unsupported engine %v", driver.Engine())
	}
}

// resolveInstance reads the vault entry, picks the driver, and builds
// the DatabaseConnection used by Open(). It does not open a pool — the
// caller decides which connect path to take (default vs database-aware).
func (h *Handler) resolveInstance(instanceID string) (Driver, *CredEntry, *pb.DatabaseConnection, error) {
	if instanceID == "" {
		return nil, nil, nil, errors.New("instance_id is required")
	}
	vault, err := h.ensureVault()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vault: %w", err)
	}
	entry, err := vault.Get(instanceID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil, fmt.Errorf("unknown instance %q (not in vault)", instanceID)
		}
		return nil, nil, nil, fmt.Errorf("vault get: %w", err)
	}
	engine, ok := engineStringToEnum(entry.Engine)
	if !ok {
		return nil, nil, nil, fmt.Errorf("unknown engine %q in vault", entry.Engine)
	}
	driver, err := DriverFor(engine)
	if err != nil {
		return nil, nil, nil, err
	}
	conn := &pb.DatabaseConnection{
		Host:       entry.Host,
		Port:       entry.Port,
		SocketPath: entry.SocketPath,
		UseTls:     entry.UseTLS,
		TlsCaPem:   entry.TLSCAPem,
	}
	return driver, entry, conn, nil
}

// openPostgresWithDatabase mirrors postgresDriver.Open but targets a
// caller-specified database name in the DSN path. Kept here rather than
// on the driver so the driver interface stays uniform across engines.
func openPostgresWithDatabase(ctx context.Context, conn *pb.DatabaseConnection, username, password, dbName string) (*sql.DB, error) {
	if conn == nil {
		return nil, errors.New("postgres: nil connection")
	}
	host := conn.GetHost()
	if host == "" {
		host = "127.0.0.1"
	}
	port := conn.GetPort()
	if port == 0 && conn.GetSocketPath() == "" {
		port = defaultPostgresPort
	}

	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(username, password),
		Path:   "/" + dbName, // url encodes path component
	}
	if conn.GetPort() == 0 && conn.GetSocketPath() != "" {
		u.Host = ""
		dir := filepath.Dir(conn.GetSocketPath())
		q := u.Query()
		q.Set("host", dir)
		u.RawQuery = q.Encode()
	} else {
		u.Host = net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	}

	q := u.Query()
	q.Set("connect_timeout", "10")
	if conn.GetUseTls() {
		q.Set("sslmode", "verify-full")
		if pem := conn.GetTlsCaPem(); pem != "" {
			caPath, err := writeTempCA(pem)
			if err != nil {
				return nil, fmt.Errorf("postgres: write CA: %w", err)
			}
			q.Set("sslrootcert", caPath)
		}
	} else {
		q.Set("sslmode", "disable")
	}
	u.RawQuery = q.Encode()

	db, err := sql.Open("postgres", u.String())
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}
	applyPoolDefaults(db)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return db, nil
}
