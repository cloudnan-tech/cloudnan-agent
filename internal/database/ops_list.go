// Package database — ops_list.go.
//
// Read-only list operations: list_dbs and list_users. These walk the
// engine's catalog tables and produce normalized DatabaseEntry /
// DatabaseUserEntry records. They are non-destructive and do not require
// confirmation tokens.
//
// SQL is engine-specific:
//
//   - list_dbs (MySQL/MariaDB) reads information_schema.schemata + tables
//     to compute size_bytes (data + indexes) and excludes the four system
//     schemas information_schema, mysql, performance_schema, sys.
//   - list_dbs (PostgreSQL) reads pg_database (filtered to non-templates,
//     excluding the bootstrap "postgres" DB) and joins to pg_get_userbyid
//     for the owner.
//   - list_users (MySQL/MariaDB) reads mysql.user joined with mysql.db,
//     aggregates granted db names per (user, host), and excludes built-in
//     internal accounts.
//   - list_users (PostgreSQL) reads pg_roles filtered to login roles and
//     uses has_database_privilege() to derive the set of databases the
//     role may CONNECT to. Role names starting with `pg_` are reserved.
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/lib/pq"

	pb "github.com/cloudnan-tech/cloudnan-agent/proto/agent"
)

// opListDBs returns all user databases on the instance referenced by req.
// Credentials are looked up from the on-disk vault by InstanceId; the
// driver is selected from the engine recorded at connect time.
func (h *Handler) opListDBs(ctx context.Context, req *pb.DatabaseInstanceRef) (*pb.DatabaseListDBsResponse, error) {
	driver, db, _, err := h.openInstance(ctx, req.GetInstanceId())
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	switch driver.Engine() {
	case pb.DatabaseEngine_DATABASE_ENGINE_MYSQL,
		pb.DatabaseEngine_DATABASE_ENGINE_MARIADB:
		return listDBsMySQL(ctx, db)
	case pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL:
		return listDBsPostgres(ctx, db)
	default:
		return nil, fmt.Errorf("list_dbs: unsupported engine %v", driver.Engine())
	}
}

// opListUsers returns all login-capable accounts on the instance.
func (h *Handler) opListUsers(ctx context.Context, req *pb.DatabaseInstanceRef) (*pb.DatabaseListUsersResponse, error) {
	driver, db, _, err := h.openInstance(ctx, req.GetInstanceId())
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	switch driver.Engine() {
	case pb.DatabaseEngine_DATABASE_ENGINE_MYSQL,
		pb.DatabaseEngine_DATABASE_ENGINE_MARIADB:
		return listUsersMySQL(ctx, db)
	case pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL:
		return listUsersPostgres(ctx, db)
	default:
		return nil, fmt.Errorf("list_users: unsupported engine %v", driver.Engine())
	}
}

// ---------- MySQL / MariaDB ----------

func listDBsMySQL(ctx context.Context, db *sql.DB) (*pb.DatabaseListDBsResponse, error) {
	const q = `
SELECT s.schema_name,
       COALESCE(s.default_character_set_name, ''),
       COALESCE(s.default_collation_name, ''),
       COALESCE(SUM(t.data_length + t.index_length), 0) AS size_bytes
  FROM information_schema.schemata s
  LEFT JOIN information_schema.tables t ON t.table_schema = s.schema_name
 WHERE s.schema_name NOT IN ('information_schema','mysql','performance_schema','sys')
 GROUP BY s.schema_name, s.default_character_set_name, s.default_collation_name
 ORDER BY s.schema_name`

	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list_dbs: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := &pb.DatabaseListDBsResponse{}
	for rows.Next() {
		var (
			name, charset, collation string
			size                     uint64
		)
		if err := rows.Scan(&name, &charset, &collation, &size); err != nil {
			return nil, fmt.Errorf("list_dbs: scan: %w", err)
		}
		out.Databases = append(out.Databases, &pb.DatabaseEntry{
			Name:      name,
			SizeBytes: size,
			Charset:   charset,
			Collation: collation,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list_dbs: rows: %w", err)
	}
	return out, nil
}

func listUsersMySQL(ctx context.Context, db *sql.DB) (*pb.DatabaseListUsersResponse, error) {
	const q = `
SELECT u.User, u.Host,
       COALESCE(GROUP_CONCAT(DISTINCT d.Db ORDER BY d.Db SEPARATOR ','), '') AS granted_databases
  FROM mysql.user u
  LEFT JOIN mysql.db d ON d.User = u.User AND d.Host = u.Host
 WHERE u.User NOT IN ('mysql.session','mysql.sys','mysql.infoschema')
 GROUP BY u.User, u.Host
 ORDER BY u.User, u.Host`

	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list_users: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := &pb.DatabaseListUsersResponse{}
	for rows.Next() {
		var user, host, granted string
		if err := rows.Scan(&user, &host, &granted); err != nil {
			return nil, fmt.Errorf("list_users: scan: %w", err)
		}
		dbs := splitCSV(granted)
		out.Users = append(out.Users, &pb.DatabaseUserEntry{
			Username:         user,
			Host:             host,
			GrantedDatabases: dbs,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list_users: rows: %w", err)
	}
	return out, nil
}

// ---------- PostgreSQL ----------

func listDBsPostgres(ctx context.Context, db *sql.DB) (*pb.DatabaseListDBsResponse, error) {
	const q = `
SELECT d.datname,
       pg_database_size(d.datname),
       pg_encoding_to_char(d.encoding),
       d.datcollate,
       pg_catalog.pg_get_userbyid(d.datdba)
  FROM pg_database d
 WHERE NOT d.datistemplate AND d.datname <> 'postgres'
 ORDER BY d.datname`

	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list_dbs: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := &pb.DatabaseListDBsResponse{}
	for rows.Next() {
		var (
			name, charset, collation, owner string
			size                            uint64
		)
		if err := rows.Scan(&name, &size, &charset, &collation, &owner); err != nil {
			return nil, fmt.Errorf("list_dbs: scan: %w", err)
		}
		out.Databases = append(out.Databases, &pb.DatabaseEntry{
			Name:      name,
			SizeBytes: size,
			Charset:   charset,
			Collation: collation,
			Owner:     owner,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list_dbs: rows: %w", err)
	}
	return out, nil
}

func listUsersPostgres(ctx context.Context, db *sql.DB) (*pb.DatabaseListUsersResponse, error) {
	const q = `
SELECT r.rolname,
       COALESCE(array_agg(DISTINCT db.datname) FILTER (WHERE db.datname IS NOT NULL), '{}')
  FROM pg_roles r
  LEFT JOIN pg_database db ON has_database_privilege(r.rolname, db.datname, 'CONNECT')
                          AND NOT db.datistemplate
                          AND db.datname <> 'postgres'
 WHERE r.rolcanlogin
   AND r.rolname NOT LIKE 'pg_%'
 GROUP BY r.rolname
 ORDER BY r.rolname`

	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list_users: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := &pb.DatabaseListUsersResponse{}
	for rows.Next() {
		var (
			user string
			dbs  []string
		)
		if err := rows.Scan(&user, pq.Array(&dbs)); err != nil {
			return nil, fmt.Errorf("list_users: scan: %w", err)
		}
		out.Users = append(out.Users, &pb.DatabaseUserEntry{
			Username:         user,
			Host:             "",
			GrantedDatabases: dbs,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list_users: rows: %w", err)
	}
	return out, nil
}

// ---------- shared helpers ----------

// openInstance is the canonical setup path used by every per-instance op:
// it resolves credentials from the vault, picks the right driver, opens a
// pool, and returns the driver + *sql.DB + the original CredEntry. The
// caller is responsible for db.Close(). On any error along the way the
// pool (if opened) is closed before returning.
func (h *Handler) openInstance(ctx context.Context, instanceID string) (Driver, *sql.DB, *CredEntry, error) {
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
	db, err := driver.Open(ctx, conn, entry.Username, entry.Password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open: %w", err)
	}
	return driver, db, entry, nil
}

// splitCSV splits a comma-separated list, dropping empty tokens. Returns
// nil for an empty/whitespace-only input so the proto field stays zero
// rather than carrying a one-element [""] slice.
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
