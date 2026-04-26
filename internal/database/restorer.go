// Package database — restorer.go.
//
// Engine-specific builders for the external restore tool invocations
// used by restore_dump. We deliberately spawn the upstream tools (mysql
// client, pg_restore) for the same reason dumper.go spawns the upstream
// dumpers: every byte the restorer reads from stdin came from the
// matching upstream dumper, so a Cloudnan export is interchangeable with
// a vendor-managed snapshot in either direction.
//
// Security posture mirrors dumper.go:
//
//   - The DB password NEVER appears on argv. We pass it via the
//     environment variable each tool documents (MYSQL_PWD for the mysql
//     client, PGPASSWORD for pg_restore).
//   - When the vault entry has UseTLS, we force TLS in the restore tool
//     too: --ssl-mode=VERIFY_CA / --ssl-mode=REQUIRED for the mysql
//     client, PGSSLMODE=verify-full for pg_restore.
//   - TLS CA material is materialized via writeTempCA, the same content-
//     addressed helper the live driver uses.
//
// The Args() method returns the program path, argv, and any extra
// environment variables to splice into the child's environment. The
// orchestrator pipes plaintext into the child's stdin and captures
// stderr in a bounded ring buffer.
//
// Engine selection notes:
//
//   - MySQL/MariaDB: we use the `mysql` client (not mysqlimport) because
//     mysqldump emits SQL statements; mysql is the matching consumer.
//     The target database is supplied as a positional argument so every
//     unqualified CREATE TABLE / INSERT lands in the new schema.
//   - PostgreSQL: we use pg_restore because export_dump pins -Fc (custom
//     format). pg_restore handles compression internally and is the only
//     restore tool that understands -Fc. Plain SQL dumps would require
//     psql; supporting them is an explicit future scope (export pins
//     -Fc, so that path is unreachable today).
package database

import (
	"errors"
	"fmt"
	"strconv"

	pb "github.com/cloudnan-tech/cloudnan-agent/proto/agent"
)

// Restorer is the engine-specific builder for a restore-tool invocation.
// Pure: no I/O until the caller invokes the returned program.
type Restorer interface {
	Engine() pb.DatabaseEngine
	// Args returns the program path, argv (NOT including the program),
	// and extra environment variables (KEY=VALUE form) to set on the
	// child process. The orchestrator should append these to os.Environ()
	// so the child inherits PATH and locale settings from the agent.
	//
	// target is the freshly-created database that will receive the
	// restore. The caller is responsible for having created it first;
	// the restore tool will fail if it does not exist.
	Args(cred *CredEntry, target string) (program string, args []string, env []string, err error)
}

// restorerFor returns the Restorer for the given engine, or an error
// for engines this PR does not support.
func restorerFor(engine pb.DatabaseEngine) (Restorer, error) {
	switch engine {
	case pb.DatabaseEngine_DATABASE_ENGINE_MYSQL,
		pb.DatabaseEngine_DATABASE_ENGINE_MARIADB:
		return &mysqlRestorer{engine: engine}, nil
	case pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL:
		return &postgresRestorer{}, nil
	default:
		return nil, fmt.Errorf("restorer: %w: %v", ErrUnknownEngine, engine)
	}
}

// ---------- MySQL / MariaDB ----------

type mysqlRestorer struct {
	engine pb.DatabaseEngine
}

func (r *mysqlRestorer) Engine() pb.DatabaseEngine { return r.engine }

func (r *mysqlRestorer) Args(cred *CredEntry, target string) (string, []string, []string, error) {
	if cred == nil {
		return "", nil, nil, errors.New("mysql restorer: nil credentials")
	}
	if target == "" {
		return "", nil, nil, errors.New("mysql restorer: empty target database")
	}
	host := cred.Host
	if host == "" {
		host = "127.0.0.1"
	}
	port := cred.Port
	if port == 0 {
		port = defaultMySQLPort
	}

	args := []string{
		"--host=" + host,
		"--port=" + strconv.FormatUint(uint64(port), 10),
		"--user=" + cred.Username,
		// utf8mb4 matches the charset we set when create_db provisions
		// the target. Without this the client would default to utf8
		// (3-byte BMP only) and emoji / supplementary-plane chars in the
		// dump would corrupt on insert.
		"--default-character-set=utf8mb4",
		// --binary-mode lets the client safely consume --hex-blob output
		// from mysqldump without trying to interpret embedded backslashes
		// as escape sequences in non-string contexts. It is harmless for
		// dumps that did not use binary blobs.
		"--binary-mode",
	}

	// TLS: if the connection is configured for TLS, demand it on the
	// restore connection as well. A CA bundle becomes a temp file on
	// disk via the content-addressed writeTempCA helper.
	if cred.UseTLS {
		if cred.TLSCAPem != "" {
			caPath, err := writeTempCA(cred.TLSCAPem)
			if err != nil {
				return "", nil, nil, fmt.Errorf("mysql restorer: write CA: %w", err)
			}
			args = append(args,
				"--ssl-mode=VERIFY_CA",
				"--ssl-ca="+caPath,
			)
		} else {
			args = append(args, "--ssl-mode=REQUIRED")
		}
	}

	// Target database as positional arg. mysqldump's single-DB mode
	// emits unqualified CREATE TABLE / INSERT, so the client must pick
	// the database explicitly with this positional. mysqldump's
	// --databases mode emits its own USE statements that override this,
	// which is also fine — the dump is self-contained either way.
	args = append(args, target)

	env := []string{}
	if cred.Password != "" {
		env = append(env, "MYSQL_PWD="+cred.Password)
	}
	return "mysql", args, env, nil
}

// ---------- PostgreSQL ----------

type postgresRestorer struct{}

func (r *postgresRestorer) Engine() pb.DatabaseEngine {
	return pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL
}

func (r *postgresRestorer) Args(cred *CredEntry, target string) (string, []string, []string, error) {
	if cred == nil {
		return "", nil, nil, errors.New("postgres restorer: nil credentials")
	}
	if target == "" {
		return "", nil, nil, errors.New("postgres restorer: empty target database")
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
		"--dbname=" + target,
		// --no-owner / --no-acl strip ownership and grant statements
		// from the restore. The dump captured the original cluster's
		// roles; the target cluster may have a completely different
		// role set, and forcing the dump's ALTER ... OWNER TO statements
		// would fail if those roles are absent. The frontend's restore
		// flow is "land the schema + data, re-grant separately".
		"--no-owner",
		"--no-acl",
		// --clean + --if-exists makes the restore idempotent if the
		// target database already has objects from a partial prior run.
		// Without these, restoring on top of any non-empty target
		// surfaces "relation already exists" errors mid-stream and the
		// transaction aborts.
		"--clean",
		"--if-exists",
		// --no-password prevents pg_restore from prompting on an
		// interactive tty; fail fast if PGPASSWORD is wrong instead of
		// hanging the agent on a stuck child process.
		"--no-password",
		// --verbose goes to stderr and is what we forward to the
		// operator in the failure path. Quiet mode hides why a restore
		// aborted (constraint violation, missing role, etc.).
		"--verbose",
	}

	env := []string{}
	if cred.Password != "" {
		env = append(env, "PGPASSWORD="+cred.Password)
	}
	if cred.UseTLS {
		// verify-full demands cert chain match AND server name match.
		// This is the only TLS mode worth using for a restore
		// connection — anything weaker means an attacker on-path can
		// MITM the entire decrypted dump stream.
		env = append(env, "PGSSLMODE=verify-full")
		if cred.TLSCAPem != "" {
			caPath, err := writeTempCA(cred.TLSCAPem)
			if err != nil {
				return "", nil, nil, fmt.Errorf("postgres restorer: write CA: %w", err)
			}
			env = append(env, "PGSSLROOTCERT="+caPath)
		}
	}
	return "pg_restore", args, env, nil
}
