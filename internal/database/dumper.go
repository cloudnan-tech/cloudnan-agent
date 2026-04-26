// Package database — dumper.go.
//
// Engine-specific builders for the external dump tool invocations used by
// export_dump. We deliberately spawn the upstream tools (mysqldump,
// pg_dump) rather than reimplement their wire dialects in Go: every byte
// they produce is a byte the operator can later restore with the same
// upstream tool. That keeps Cloudnan's exports interchangeable with
// vendor-managed snapshots.
//
// Security posture:
//
//   - The DB password NEVER appears on argv. We pass it via the
//     environment variable that each tool documents (MYSQL_PWD for
//     mysqldump, PGPASSWORD for pg_dump). This keeps it out of `ps` output
//     for any other user on the host.
//   - When the vault entry has UseTLS, we force TLS in the dump tool too:
//     --ssl-mode=REQUIRED for mysqldump (or VERIFY_CA when a CA PEM is
//     present) and PGSSLMODE=verify-full for pg_dump. A managed DB that is
//     accessed over TLS in normal ops must not silently fall back to
//     plaintext during a backup.
//   - TLS CA material is materialized via writeTempCA, the same content-
//     addressed helper the live driver uses. The temp file is owned by
//     the agent UID and lives for the process lifetime.
//
// The Args() method returns the program path, argv, and any extra
// environment variables to splice into the child's environment. The
// caller is responsible for spawning the process and piping stdout into
// the encryption + upload pipeline. Stderr is captured separately so that
// failures from the dump tool (auth errors, missing tables, lock waits,
// etc.) surface in the export_dump error chunk.
package database

import (
	"errors"
	"fmt"
	"strconv"

	pb "github.com/cloudnan-tech/cloudnan-agent/proto/agent"
)

// Dumper is the engine-specific builder for a dump-tool invocation. It is
// pure: no I/O happens until the caller invokes the returned program.
type Dumper interface {
	Engine() pb.DatabaseEngine
	// Args returns the program path, argv (NOT including the program), and
	// extra environment variables (KEY=VALUE form) to set on the child
	// process. The agent runtime should append these to os.Environ() so
	// the child inherits PATH and locale settings from the agent.
	Args(cred *CredEntry, dbNames []string) (program string, args []string, env []string, err error)
}

// dumperFor returns the Dumper for the given engine, or an error for
// engines this PR does not support.
func dumperFor(engine pb.DatabaseEngine) (Dumper, error) {
	switch engine {
	case pb.DatabaseEngine_DATABASE_ENGINE_MYSQL,
		pb.DatabaseEngine_DATABASE_ENGINE_MARIADB:
		return &mysqlDumper{engine: engine}, nil
	case pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL:
		return &postgresDumper{}, nil
	default:
		return nil, fmt.Errorf("dumper: %w: %v", ErrUnknownEngine, engine)
	}
}

// ---------- MySQL / MariaDB ----------

type mysqlDumper struct {
	engine pb.DatabaseEngine
}

func (d *mysqlDumper) Engine() pb.DatabaseEngine { return d.engine }

func (d *mysqlDumper) Args(cred *CredEntry, dbNames []string) (string, []string, []string, error) {
	if cred == nil {
		return "", nil, nil, errors.New("mysql dumper: nil credentials")
	}
	host := cred.Host
	if host == "" {
		host = "127.0.0.1"
	}
	port := cred.Port
	if port == 0 {
		port = defaultMySQLPort
	}

	// Order matters only for human readability; mysqldump parses any order.
	args := []string{
		"--host=" + host,
		"--port=" + strconv.FormatUint(uint64(port), 10),
		"--user=" + cred.Username,
		// --single-transaction takes a consistent snapshot under InnoDB
		// without locking writers. Critical for live exports.
		"--single-transaction",
		// --quick streams rows one at a time instead of buffering an entire
		// table in RAM — required for tables that don't fit in memory.
		"--quick",
		// --routines + --triggers + --events captures the full schema.
		// Without these the dump silently omits stored procs / triggers.
		"--routines",
		"--triggers",
		"--events",
		// --hex-blob keeps binary columns safe across charset translations.
		"--hex-blob",
		// --set-gtid-purged=OFF prevents emitting SET @@GLOBAL.GTID_PURGED
		// statements that fail to import on any non-GTID-aware target.
		// MariaDB ignores this flag (unrecognized but harmless on >=10.1
		// when paired with --force? — to stay portable across MySQL 5.7,
		// 8.x, and MariaDB we only emit it for MySQL.
	}
	if d.engine == pb.DatabaseEngine_DATABASE_ENGINE_MYSQL {
		args = append(args, "--set-gtid-purged=OFF")
	}

	// TLS: if the connection is configured for TLS, demand it on the dump
	// connection as well. A CA bundle becomes a temp file on disk.
	if cred.UseTLS {
		if cred.TLSCAPem != "" {
			caPath, err := writeTempCA(cred.TLSCAPem)
			if err != nil {
				return "", nil, nil, fmt.Errorf("mysql dumper: write CA: %w", err)
			}
			args = append(args,
				"--ssl-mode=VERIFY_CA",
				"--ssl-ca="+caPath,
			)
		} else {
			args = append(args, "--ssl-mode=REQUIRED")
		}
	}

	switch len(dbNames) {
	case 0:
		args = append(args, "--all-databases", "--add-drop-database")
	case 1:
		// Single-DB mode: mysqldump emits CREATE TABLE and data without a
		// USE statement. The restore side picks the database explicitly.
		args = append(args, dbNames[0])
	default:
		// Multiple specific databases: --databases switches mysqldump into
		// the mode where it emits USE statements between databases AND
		// CREATE DATABASE for each.
		args = append(args, "--databases", "--add-drop-database")
		args = append(args, dbNames...)
	}

	env := []string{}
	if cred.Password != "" {
		env = append(env, "MYSQL_PWD="+cred.Password)
	}
	return "mysqldump", args, env, nil
}

// ---------- PostgreSQL ----------

type postgresDumper struct{}

func (d *postgresDumper) Engine() pb.DatabaseEngine {
	return pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL
}

func (d *postgresDumper) Args(cred *CredEntry, dbNames []string) (string, []string, []string, error) {
	if cred == nil {
		return "", nil, nil, errors.New("postgres dumper: nil credentials")
	}
	if len(dbNames) == 0 {
		return "", nil, nil, errors.New("postgres dumper: at least one database name is required (use pg_dumpall externally for full-cluster dumps)")
	}
	if len(dbNames) > 1 {
		// pg_dump is per-database. The frontend / control plane is expected
		// to issue one export_dump per database for Postgres. This matches
		// how DBaaS providers (RDS, Cloud SQL) surface backups.
		return "", nil, nil, errors.New("postgres dumper: exactly one database per export is supported; issue separate export_dump calls per database")
	}

	host := cred.Host
	if host == "" {
		host = "127.0.0.1"
	}
	port := cred.Port
	if port == 0 {
		port = defaultPostgresPort
	}

	args := []string{
		"--host=" + host,
		"--port=" + strconv.FormatUint(uint64(port), 10),
		"--username=" + cred.Username,
		// -Fc = custom format: compressed by pg_dump itself, restorable with
		// pg_restore, and the only format that supports parallel restore.
		"-Fc",
		// --no-password prevents pg_dump from prompting on an interactive
		// tty; fail fast if PGPASSWORD is wrong instead of hanging.
		"--no-password",
		// --verbose goes to stderr and is what we forward to the operator
		// in the failure path. Quiet mode hides why a dump aborted.
		"--verbose",
		dbNames[0],
	}

	env := []string{}
	if cred.Password != "" {
		env = append(env, "PGPASSWORD="+cred.Password)
	}
	if cred.UseTLS {
		// verify-full demands the cert chain matches AND the server name
		// matches. This is the only TLS mode worth using for a backup
		// connection — anything weaker means an attacker on-path can MITM
		// the entire dump stream.
		env = append(env, "PGSSLMODE=verify-full")
		if cred.TLSCAPem != "" {
			caPath, err := writeTempCA(cred.TLSCAPem)
			if err != nil {
				return "", nil, nil, fmt.Errorf("postgres dumper: write CA: %w", err)
			}
			env = append(env, "PGSSLROOTCERT="+caPath)
		}
	}
	return "pg_dump", args, env, nil
}
