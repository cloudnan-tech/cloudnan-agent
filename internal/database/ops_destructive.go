// Package database — ops_destructive.go.
//
// Destructive operations: drop_db and drop_user. Unlike create/grant,
// these are not recoverable from the agent's perspective once issued —
// a dropped database is dropped — so they require a confirmation token
// minted by the control plane and verified locally before any SQL is
// executed.
//
// Token verification is the responsibility of handler.go (it has access
// to the original request including the token); the functions in this
// file assume the caller has already validated the token. They focus on
// the engine-specific SQL only.
//
// Engine notes for drop_db on PostgreSQL: PostgreSQL refuses to DROP a
// database that has any open backend, so we first iterate every PID in
// pg_stat_activity for the target db name and pg_terminate_backend()
// each. We never terminate our own backend (pid <> pg_backend_pid()).
//
// Engine notes for drop_user on PostgreSQL: a role that owns objects or
// has been granted privileges cannot simply be dropped. We REASSIGN OWNED
// to postgres (the bootstrap superuser) and DROP OWNED to remove residual
// grants before issuing DROP USER.
package database

import (
	"context"
	"database/sql"
	"fmt"

	pb "github.com/cloudnan-tech/cloudnan-agent/proto/agent"
)

// opDropDB drops the named database. The caller is expected to have
// already verified req.GetConfirmationToken() against verifyOpToken.
func (h *Handler) opDropDB(ctx context.Context, req *pb.DatabaseDropDBRequest) (*pb.DatabaseDropDBResponse, error) {
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
		stmt := "DROP DATABASE " + quoteMySQLIdent(req.GetDatabaseName())
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return nil, fmt.Errorf("drop_db: %w", err)
		}
	case pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL:
		if err := terminatePostgresBackends(ctx, db, req.GetDatabaseName()); err != nil {
			return nil, fmt.Errorf("drop_db: terminate backends: %w", err)
		}
		stmt := "DROP DATABASE " + quotePostgresIdent(req.GetDatabaseName())
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return nil, fmt.Errorf("drop_db: %w", err)
		}
	default:
		return nil, fmt.Errorf("drop_db: unsupported engine %v", driver.Engine())
	}

	return &pb.DatabaseDropDBResponse{
		Success: true,
		Message: fmt.Sprintf("database %s dropped", req.GetDatabaseName()),
	}, nil
}

// opDropUser drops the named login role. Caller must have already
// verified req.GetConfirmationToken().
func (h *Handler) opDropUser(ctx context.Context, req *pb.DatabaseDropUserRequest) (*pb.DatabaseDropUserResponse, error) {
	if err := validateNonEmpty("username", req.GetUsername()); err != nil {
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
			"DROP USER '%s'@'%s'",
			escapeSQLString(req.GetUsername()),
			escapeSQLString(host),
		)
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return nil, fmt.Errorf("drop_user: %w", err)
		}
		return &pb.DatabaseDropUserResponse{
			Success: true,
			Message: fmt.Sprintf("user %s@%s dropped", req.GetUsername(), host),
		}, nil
	case pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL:
		userIdent := quotePostgresIdent(req.GetUsername())
		// Order matters: REASSIGN moves owned objects, DROP OWNED removes
		// residual grants/defaults, then the role can be dropped. Each
		// step is idempotent enough that running on a clean role is fine.
		if _, err := db.ExecContext(ctx, fmt.Sprintf("REASSIGN OWNED BY %s TO postgres", userIdent)); err != nil {
			return nil, fmt.Errorf("drop_user: reassign owned: %w", err)
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf("DROP OWNED BY %s", userIdent)); err != nil {
			return nil, fmt.Errorf("drop_user: drop owned: %w", err)
		}
		if _, err := db.ExecContext(ctx, "DROP USER "+userIdent); err != nil {
			return nil, fmt.Errorf("drop_user: %w", err)
		}
		return &pb.DatabaseDropUserResponse{
			Success: true,
			Message: fmt.Sprintf("role %s dropped", req.GetUsername()),
		}, nil
	default:
		return nil, fmt.Errorf("drop_user: unsupported engine %v", driver.Engine())
	}
}

// terminatePostgresBackends kicks every connection (other than ours) off
// the named database so the subsequent DROP DATABASE will succeed. The
// pg_terminate_backend call returns a boolean per backend; we ignore the
// row data because failures to terminate a single PID are not fatal —
// DROP DATABASE will surface the real problem if any backend lingers.
func terminatePostgresBackends(ctx context.Context, db *sql.DB, dbName string) error {
	const q = `
SELECT pg_terminate_backend(pid)
  FROM pg_stat_activity
 WHERE datname = $1
   AND pid <> pg_backend_pid()`
	rows, err := db.QueryContext(ctx, q, dbName)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var ignored bool
		if err := rows.Scan(&ignored); err != nil {
			return err
		}
	}
	return rows.Err()
}
