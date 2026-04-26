// Package database — ops_create.go.
//
// Non-destructive creation/grant operations: create_db, create_user, grant.
// These do not require a confirmation token because they are additive —
// the worst-case mistake adds an unwanted role or schema, which is
// trivially reversible. Drop and revoke flow through ops_destructive.go
// and require a token.
//
// All identifiers are passed through quoteMySQLIdent / quotePostgresIdent
// before being interpolated into SQL strings; password and host literal
// values go through escapeSQLString and are wrapped in single quotes.
//
// Engine notes:
//
//   - PostgreSQL's CREATE DATABASE cannot run inside a transaction, so we
//     issue it via ExecContext on the raw connection. The optional owner
//     user is created with WITH LOGIN PASSWORD; ownership transfer uses
//     ALTER DATABASE ... OWNER TO when grant_all_on_db is requested.
//   - MySQL/MariaDB does not have a native "create database with owner"
//     verb, so we issue CREATE USER + GRANT ... ON db.* TO user@host as
//     two separate statements when an owner is supplied. If user creation
//     fails after the database is already created, we drop the database
//     to keep the agent's mutations atomic from the caller's perspective.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	pb "github.com/cloudnan-tech/cloudnan-agent/proto/agent"
)

// defaultMySQLCharset / defaultMySQLCollation are used when the request
// does not pin them. utf8mb4 is the current best-practice default for
// MySQL 8 / MariaDB 10.5+.
const (
	defaultMySQLCharset   = "utf8mb4"
	defaultMySQLCollation = "utf8mb4_unicode_ci"
	defaultMySQLHost      = "%"
)

// opCreateDB creates a database on the target instance, optionally
// provisioning a companion owner role.
func (h *Handler) opCreateDB(ctx context.Context, req *pb.DatabaseCreateDBRequest) (*pb.DatabaseCreateDBResponse, error) {
	if err := validateNonEmpty("database_name", req.GetDatabaseName()); err != nil {
		return nil, err
	}
	driver, db, _, err := h.openInstance(ctx, req.GetInstance().GetInstanceId())
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	switch driver.Engine() {
	case pb.DatabaseEngine_DATABASE_ENGINE_MYSQL,
		pb.DatabaseEngine_DATABASE_ENGINE_MARIADB:
		return createDBMySQL(ctx, db, req)
	case pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL:
		return createDBPostgres(ctx, db, req)
	default:
		return nil, fmt.Errorf("create_db: unsupported engine %v", driver.Engine())
	}
}

// opCreateUser creates a login role / user account on the target instance.
// On Postgres host is ignored (no host concept).
func (h *Handler) opCreateUser(ctx context.Context, req *pb.DatabaseCreateUserRequest) (*pb.DatabaseCreateUserResponse, error) {
	if err := validateNonEmpty("username", req.GetUsername()); err != nil {
		return nil, err
	}
	if err := validateNonEmpty("password", req.GetPassword()); err != nil {
		return nil, err
	}
	driver, db, _, err := h.openInstance(ctx, req.GetInstance().GetInstanceId())
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	switch driver.Engine() {
	case pb.DatabaseEngine_DATABASE_ENGINE_MYSQL,
		pb.DatabaseEngine_DATABASE_ENGINE_MARIADB:
		host := req.GetHost()
		if host == "" {
			host = defaultMySQLHost
		}
		stmt := fmt.Sprintf(
			"CREATE USER '%s'@'%s' IDENTIFIED BY '%s'",
			escapeSQLString(req.GetUsername()),
			escapeSQLString(host),
			escapeSQLString(req.GetPassword()),
		)
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return nil, fmt.Errorf("create_user: %w", err)
		}
		return &pb.DatabaseCreateUserResponse{
			Success: true,
			Message: fmt.Sprintf("user %s@%s created", req.GetUsername(), host),
		}, nil
	case pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL:
		stmt := fmt.Sprintf(
			"CREATE USER %s WITH LOGIN PASSWORD '%s'",
			quotePostgresIdent(req.GetUsername()),
			escapeSQLString(req.GetPassword()),
		)
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return nil, fmt.Errorf("create_user: %w", err)
		}
		return &pb.DatabaseCreateUserResponse{
			Success: true,
			Message: fmt.Sprintf("role %s created", req.GetUsername()),
		}, nil
	default:
		return nil, fmt.Errorf("create_user: unsupported engine %v", driver.Engine())
	}
}

// opGrant grants (or revokes, when req.Revoke is true) a privilege set on
// a database to a user. Privilege names are validated against the
// whitelist; ALL / empty list expands to "ALL PRIVILEGES".
func (h *Handler) opGrant(ctx context.Context, req *pb.DatabaseGrantRequest) (*pb.DatabaseGrantResponse, error) {
	if err := validateNonEmpty("username", req.GetUsername()); err != nil {
		return nil, err
	}
	if err := validateNonEmpty("database_name", req.GetDatabaseName()); err != nil {
		return nil, err
	}
	if err := validatePrivilegesList(req.GetPrivileges()); err != nil {
		return nil, fmt.Errorf("grant: %w", err)
	}
	privCSV := normalizePrivileges(req.GetPrivileges())

	driver, db, _, err := h.openInstance(ctx, req.GetInstance().GetInstanceId())
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	verb, prep := "GRANT", "TO"
	if req.GetRevoke() {
		verb, prep = "REVOKE", "FROM"
	}

	switch driver.Engine() {
	case pb.DatabaseEngine_DATABASE_ENGINE_MYSQL,
		pb.DatabaseEngine_DATABASE_ENGINE_MARIADB:
		host := req.GetHost()
		if host == "" {
			host = defaultMySQLHost
		}
		stmt := fmt.Sprintf(
			"%s %s ON %s.* %s '%s'@'%s'",
			verb, privCSV,
			quoteMySQLIdent(req.GetDatabaseName()),
			prep,
			escapeSQLString(req.GetUsername()),
			escapeSQLString(host),
		)
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return nil, fmt.Errorf("grant: %w", err)
		}
		if _, err := db.ExecContext(ctx, "FLUSH PRIVILEGES"); err != nil {
			return nil, fmt.Errorf("grant: flush: %w", err)
		}
		return &pb.DatabaseGrantResponse{
			Success: true,
			Message: fmt.Sprintf("%s %s on %s for %s@%s", verb, privCSV, req.GetDatabaseName(), req.GetUsername(), host),
		}, nil
	case pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL:
		stmt := fmt.Sprintf(
			"%s %s ON DATABASE %s %s %s",
			verb, privCSV,
			quotePostgresIdent(req.GetDatabaseName()),
			prep,
			quotePostgresIdent(req.GetUsername()),
		)
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return nil, fmt.Errorf("grant: %w", err)
		}
		return &pb.DatabaseGrantResponse{
			Success: true,
			Message: fmt.Sprintf("%s %s on %s for %s", verb, privCSV, req.GetDatabaseName(), req.GetUsername()),
		}, nil
	default:
		return nil, fmt.Errorf("grant: unsupported engine %v", driver.Engine())
	}
}

// ---------- engine-specific create_db ----------

func createDBMySQL(ctx context.Context, db *sql.DB, req *pb.DatabaseCreateDBRequest) (*pb.DatabaseCreateDBResponse, error) {
	charset := req.GetCharset()
	if charset == "" {
		charset = defaultMySQLCharset
	}
	collation := req.GetCollation()
	if collation == "" {
		collation = defaultMySQLCollation
	}
	if !isSimpleIdent(charset) {
		return nil, fmt.Errorf("create_db: charset %q rejected by whitelist", charset)
	}
	if !isSimpleIdent(collation) {
		return nil, fmt.Errorf("create_db: collation %q rejected by whitelist", collation)
	}

	dbIdent := quoteMySQLIdent(req.GetDatabaseName())
	createStmt := fmt.Sprintf(
		"CREATE DATABASE %s CHARACTER SET %s COLLATE %s",
		dbIdent, charset, collation,
	)
	if _, err := db.ExecContext(ctx, createStmt); err != nil {
		return nil, fmt.Errorf("create_db: %w", err)
	}

	owner := req.GetOwner()
	if owner == nil {
		return &pb.DatabaseCreateDBResponse{
			Success: true,
			Message: fmt.Sprintf("database %s created", req.GetDatabaseName()),
		}, nil
	}
	if err := validateNonEmpty("owner.username", owner.GetUsername()); err != nil {
		// Roll back the database create so caller can retry cleanly.
		_, _ = db.ExecContext(ctx, "DROP DATABASE "+dbIdent)
		return nil, fmt.Errorf("create_db: %w", err)
	}
	if err := validateNonEmpty("owner.password", owner.GetPassword()); err != nil {
		_, _ = db.ExecContext(ctx, "DROP DATABASE "+dbIdent)
		return nil, fmt.Errorf("create_db: %w", err)
	}
	host := owner.GetHost()
	if host == "" {
		host = defaultMySQLHost
	}

	createUser := fmt.Sprintf(
		"CREATE USER '%s'@'%s' IDENTIFIED BY '%s'",
		escapeSQLString(owner.GetUsername()),
		escapeSQLString(host),
		escapeSQLString(owner.GetPassword()),
	)
	if _, err := db.ExecContext(ctx, createUser); err != nil {
		// Compensating drop of the just-created database so the caller's
		// mental model — either the whole op succeeded or nothing changed —
		// holds across a partial failure.
		_, _ = db.ExecContext(ctx, "DROP DATABASE "+dbIdent)
		return nil, fmt.Errorf("create_db: create owner user: %w", err)
	}

	if owner.GetGrantAllOnDb() {
		grant := fmt.Sprintf(
			"GRANT ALL PRIVILEGES ON %s.* TO '%s'@'%s'",
			dbIdent,
			escapeSQLString(owner.GetUsername()),
			escapeSQLString(host),
		)
		if _, err := db.ExecContext(ctx, grant); err != nil {
			// Best-effort rollback of the user and database.
			_, _ = db.ExecContext(ctx, fmt.Sprintf(
				"DROP USER '%s'@'%s'",
				escapeSQLString(owner.GetUsername()),
				escapeSQLString(host),
			))
			_, _ = db.ExecContext(ctx, "DROP DATABASE "+dbIdent)
			return nil, fmt.Errorf("create_db: grant: %w", err)
		}
		if _, err := db.ExecContext(ctx, "FLUSH PRIVILEGES"); err != nil {
			return nil, fmt.Errorf("create_db: flush: %w", err)
		}
	}

	return &pb.DatabaseCreateDBResponse{
		Success: true,
		Message: fmt.Sprintf("database %s and owner %s@%s created", req.GetDatabaseName(), owner.GetUsername(), host),
	}, nil
}

func createDBPostgres(ctx context.Context, db *sql.DB, req *pb.DatabaseCreateDBRequest) (*pb.DatabaseCreateDBResponse, error) {
	dbIdent := quotePostgresIdent(req.GetDatabaseName())
	// CREATE DATABASE in PostgreSQL cannot run inside a transaction; the
	// driver's auto-commit on a single ExecContext is what we want here.
	createStmt := fmt.Sprintf(
		"CREATE DATABASE %s ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0",
		dbIdent,
	)
	if _, err := db.ExecContext(ctx, createStmt); err != nil {
		return nil, fmt.Errorf("create_db: %w", err)
	}

	owner := req.GetOwner()
	if owner == nil {
		return &pb.DatabaseCreateDBResponse{
			Success: true,
			Message: fmt.Sprintf("database %s created", req.GetDatabaseName()),
		}, nil
	}
	if err := validateNonEmpty("owner.username", owner.GetUsername()); err != nil {
		_, _ = db.ExecContext(ctx, "DROP DATABASE "+dbIdent)
		return nil, fmt.Errorf("create_db: %w", err)
	}
	if err := validateNonEmpty("owner.password", owner.GetPassword()); err != nil {
		_, _ = db.ExecContext(ctx, "DROP DATABASE "+dbIdent)
		return nil, fmt.Errorf("create_db: %w", err)
	}

	userIdent := quotePostgresIdent(owner.GetUsername())
	createUser := fmt.Sprintf(
		"CREATE USER %s WITH LOGIN PASSWORD '%s'",
		userIdent,
		escapeSQLString(owner.GetPassword()),
	)
	if _, err := db.ExecContext(ctx, createUser); err != nil {
		_, _ = db.ExecContext(ctx, "DROP DATABASE "+dbIdent)
		return nil, fmt.Errorf("create_db: create owner user: %w", err)
	}

	if owner.GetGrantAllOnDb() {
		grant := fmt.Sprintf("GRANT ALL PRIVILEGES ON DATABASE %s TO %s", dbIdent, userIdent)
		if _, err := db.ExecContext(ctx, grant); err != nil {
			_, _ = db.ExecContext(ctx, "DROP USER "+userIdent)
			_, _ = db.ExecContext(ctx, "DROP DATABASE "+dbIdent)
			return nil, fmt.Errorf("create_db: grant: %w", err)
		}
		alter := fmt.Sprintf("ALTER DATABASE %s OWNER TO %s", dbIdent, userIdent)
		if _, err := db.ExecContext(ctx, alter); err != nil {
			return nil, fmt.Errorf("create_db: alter owner: %w", err)
		}
	}

	return &pb.DatabaseCreateDBResponse{
		Success: true,
		Message: fmt.Sprintf("database %s and owner %s created", req.GetDatabaseName(), owner.GetUsername()),
	}, nil
}

// ---------- helpers ----------

// normalizePrivileges returns the SQL fragment that goes between the verb
// and the ON keyword. Empty list and ["ALL"] both map to "ALL PRIVILEGES";
// any other list is joined with ", ". Inputs are already validated.
func normalizePrivileges(privs []string) string {
	if len(privs) == 0 {
		return "ALL PRIVILEGES"
	}
	if len(privs) == 1 && strings.EqualFold(privs[0], "ALL") {
		return "ALL PRIVILEGES"
	}
	return strings.Join(privs, ", ")
}

// isSimpleIdent enforces a conservative whitelist for charset/collation
// names: letters, digits, underscores. Anything else is rejected; we
// would rather refuse a request than splice an attacker-controlled token
// into CREATE DATABASE.
func isSimpleIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_':
		default:
			return false
		}
	}
	return true
}

