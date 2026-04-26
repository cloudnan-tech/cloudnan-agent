// Package database — ops_query.go.
//
// Streaming exec_query handler. Classifies the inbound SQL as read-only
// or destructive, enforces the read-only gate (rejecting destructive
// statements when DatabaseExecQueryRequest.read_only=true) or the
// confirmation-token gate (when read_only=false), opens the right
// instance, and executes the statement.
//
// Result delivery is NDJSON over the agent's existing stdout-chunk
// stream: every emitted chunk is exactly one JSON-encoded
// pb.DatabaseQueryResultChunk followed by '\n'. The control plane reads
// chunks line-by-line. The chunk types form a fixed sequence:
//
//	[Header] [Row]* [Footer]              — successful query
//	[Error]                                 — any failure (validation, token,
//	                                          open, execute, scan, classifier)
//
// Errors NEVER cause the function to return a non-nil error from
// opExecQuery — instead they are emitted as Error chunks so the user
// gets a structured failure in the UI. Returning a non-nil error is
// reserved for transport-level failures (e.g. emit() itself returning
// an error, though emit is currently fire-and-forget).
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	mysqldrv "github.com/go-sql-driver/mysql"
	"github.com/lib/pq"

	pb "github.com/cloudnan-tech/cloudnan-agent/proto/agent"
)

const (
	// queryRowLimitDefault is the row cap applied when the request does
	// not specify one. Mirrors the per-page limit the UI uses.
	queryRowLimitDefault uint32 = 1000
	// queryRowLimitMax is a hard cap to keep a single query from
	// holding open the agent's connection for an unbounded amount of
	// time. The UI may request higher but the agent quietly clamps.
	queryRowLimitMax uint32 = 100000
	// queryTimeoutDefault is the per-query deadline applied when the
	// request does not specify one.
	queryTimeoutDefault uint32 = 30
	// queryTimeoutMax is the upper bound — even an admin user cannot
	// pin an instance forever.
	queryTimeoutMax uint32 = 600
)

// opExecQuery is the agent-side exec_query implementation. It always
// emits at least one chunk: either a header+rows+footer for success or
// a single error chunk for failure. The returned error is reserved for
// transport-level failures only.
func (h *Handler) opExecQuery(ctx context.Context, req *pb.DatabaseExecQueryRequest, emit func(string)) error {
	// ---- 1. validate inputs ----
	if req == nil {
		return emitChunk(emit, errChunk("E_INVALID_REQUEST", "nil request", 0))
	}
	if req.GetSql() == "" {
		return emitChunk(emit, errChunk("E_INVALID_REQUEST", "sql is required", 0))
	}
	if req.GetInstance().GetInstanceId() == "" {
		return emitChunk(emit, errChunk("E_INVALID_REQUEST", "instance.instance_id is required", 0))
	}

	rowLimit := req.GetRowLimit()
	if rowLimit == 0 {
		rowLimit = queryRowLimitDefault
	}
	if rowLimit > queryRowLimitMax {
		rowLimit = queryRowLimitMax
	}
	timeoutSec := req.GetTimeoutSeconds()
	if timeoutSec == 0 {
		timeoutSec = queryTimeoutDefault
	}
	if timeoutSec > queryTimeoutMax {
		timeoutSec = queryTimeoutMax
	}

	// ---- 2. classify the statement ----
	// Engine determines a couple of dialect-specific corner cases (dollar
	// quoting in postgres) but the leading-keyword decision is uniform.
	engineEnum, _ := classifyEngine(h, req.GetInstance().GetInstanceId())
	kind, err := ClassifyStatement(req.GetSql(), engineEnum)
	if err != nil {
		return emitChunk(emit, errChunk("E_PARSE", err.Error(), 0))
	}

	// ---- 3. read-only gate ----
	if kind == StatementWrite && req.GetReadOnly() {
		return emitChunk(emit, errChunk("E_READ_ONLY", "read-only mode rejected a destructive statement", 0))
	}

	// ---- 4. confirmation-token gate ----
	if kind == StatementWrite && !req.GetReadOnly() {
		if err := verifyOpToken(req.GetConfirmationToken(), "exec_query", req.GetInstance().GetInstanceId(), ""); err != nil {
			return emitChunk(emit, errChunk("E_TOKEN", err.Error(), 0))
		}
	}

	// ---- 5. open instance (engine-aware DB selection) ----
	driver, db, _, err := h.openInstanceForDatabase(ctx, req.GetInstance().GetInstanceId(), req.GetDatabaseName())
	if err != nil {
		return emitChunk(emit, errChunk("E_OPEN", err.Error(), 0))
	}
	defer func() { _ = db.Close() }()

	// ---- 6. timeout ----
	qctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	// ---- 7. execute ----
	start := time.Now()
	if kind == StatementRead {
		return runQuery(qctx, db, req.GetSql(), rowLimit, start, driver, emit)
	}
	return runExec(qctx, db, req.GetSql(), start, driver, emit)
}

// runQuery streams a SELECT-style result set as Header + Row* + Footer.
func runQuery(ctx context.Context, db *sql.DB, query string, rowLimit uint32, start time.Time, driver Driver, emit func(string)) error {
	rs, err := db.QueryContext(ctx, query)
	if err != nil {
		code, line := classifyDriverError(err, driver)
		return emitChunk(emit, errChunk(code, err.Error(), line))
	}
	defer func() { _ = rs.Close() }()

	cols, err := rs.Columns()
	if err != nil {
		return emitChunk(emit, errChunk("E_COLUMNS", err.Error(), 0))
	}
	colTypes, err := rs.ColumnTypes()
	if err != nil {
		return emitChunk(emit, errChunk("E_COLUMN_TYPES", err.Error(), 0))
	}
	typeNames := make([]string, len(colTypes))
	for i, ct := range colTypes {
		typeNames[i] = ct.DatabaseTypeName()
	}

	if err := emitChunk(emit, &pb.DatabaseQueryResultChunk{
		Body: &pb.DatabaseQueryResultChunk_Header{Header: &pb.DatabaseQueryHeader{
			Columns:     cols,
			ColumnTypes: typeNames,
		}},
	}); err != nil {
		return err
	}

	var (
		rowCount  uint64
		truncated bool
	)
	for rs.Next() {
		if rowCount >= uint64(rowLimit) {
			truncated = true
			break
		}
		cells, isNull, err := scanRow(rs, len(cols))
		if err != nil {
			return emitChunk(emit, errChunk("E_SCAN", err.Error(), 0))
		}
		if err := emitChunk(emit, &pb.DatabaseQueryResultChunk{
			Body: &pb.DatabaseQueryResultChunk_Row{Row: &pb.DatabaseQueryRow{
				Cells:  cells,
				IsNull: isNull,
			}},
		}); err != nil {
			return err
		}
		rowCount++
	}
	if err := rs.Err(); err != nil {
		code, line := classifyDriverError(err, driver)
		return emitChunk(emit, errChunk(code, err.Error(), line))
	}

	return emitChunk(emit, &pb.DatabaseQueryResultChunk{
		Body: &pb.DatabaseQueryResultChunk_Footer{Footer: &pb.DatabaseQueryFooter{
			RowCount:     rowCount,
			AffectedRows: 0,
			ElapsedMs:    uint64(time.Since(start).Milliseconds()),
			Truncated:    truncated,
		}},
	})
}

// runExec streams a non-SELECT execution result as a synthetic
// affected_rows column header and an affected-rows footer. We expose the
// affected count both in the header (single cell, single row would
// double-encode it) and authoritatively in the footer's affected_rows
// field — the frontend reads from the footer.
func runExec(ctx context.Context, db *sql.DB, query string, start time.Time, driver Driver, emit func(string)) error {
	res, err := db.ExecContext(ctx, query)
	if err != nil {
		code, line := classifyDriverError(err, driver)
		return emitChunk(emit, errChunk(code, err.Error(), line))
	}
	affected, _ := res.RowsAffected() // ignore — not all drivers report it

	if err := emitChunk(emit, &pb.DatabaseQueryResultChunk{
		Body: &pb.DatabaseQueryResultChunk_Header{Header: &pb.DatabaseQueryHeader{
			Columns:     []string{"affected_rows"},
			ColumnTypes: []string{"int64"},
		}},
	}); err != nil {
		return err
	}
	return emitChunk(emit, &pb.DatabaseQueryResultChunk{
		Body: &pb.DatabaseQueryResultChunk_Footer{Footer: &pb.DatabaseQueryFooter{
			RowCount:     0,
			AffectedRows: uint64(maxInt64(affected, 0)),
			ElapsedMs:    uint64(time.Since(start).Milliseconds()),
			Truncated:    false,
		}},
	})
}

// classifyDriverError extracts a stable error code and (when available)
// a 1-based line number from an engine-specific driver error. Falls back
// to E_DRIVER for plain database/sql errors.
func classifyDriverError(err error, _ Driver) (code string, line uint32) {
	if err == nil {
		return "", 0
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "E_TIMEOUT", 0
	}
	if errors.Is(err, context.Canceled) {
		return "E_CANCELED", 0
	}
	var myErr *mysqldrv.MySQLError
	if errors.As(err, &myErr) {
		return "MY-" + strconv.FormatUint(uint64(myErr.Number), 10), 0
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return "PG-" + string(pqErr.Code), parsePostgresPosition(pqErr.Position)
	}
	return "E_DRIVER", 0
}

// parsePostgresPosition converts pq.Error.Position (a 1-based byte
// offset, as a decimal string) to a 1-based line number. We don't have
// the original SQL here, so we conservatively report the offset as the
// line — the frontend treats Line==0 as "unknown".
func parsePostgresPosition(pos string) uint32 {
	if pos == "" {
		return 0
	}
	n, err := strconv.ParseUint(pos, 10, 32)
	if err != nil {
		return 0
	}
	// Without the SQL text we can't translate offset→line; surface the
	// raw character position. The frontend renders it under "near
	// character N" which is what psql does.
	return uint32(n)
}

// classifyEngine looks up the engine recorded at connect time without
// opening a pool. Returns DATABASE_ENGINE_UNSPECIFIED when the instance
// is unknown — the caller will hit the same error again at openInstance
// time, but only after running the classifier on the engine-agnostic
// path, which is fine.
func classifyEngine(h *Handler, instanceID string) (pb.DatabaseEngine, error) {
	if instanceID == "" {
		return pb.DatabaseEngine_DATABASE_ENGINE_UNSPECIFIED, errors.New("instance_id is required")
	}
	vault, err := h.ensureVault()
	if err != nil {
		return pb.DatabaseEngine_DATABASE_ENGINE_UNSPECIFIED, err
	}
	entry, err := vault.Get(instanceID)
	if err != nil {
		return pb.DatabaseEngine_DATABASE_ENGINE_UNSPECIFIED, err
	}
	enum, ok := engineStringToEnum(entry.Engine)
	if !ok {
		return pb.DatabaseEngine_DATABASE_ENGINE_UNSPECIFIED, fmt.Errorf("unknown engine %q", entry.Engine)
	}
	return enum, nil
}

// errChunk is a one-liner for building an error-bearing result chunk.
func errChunk(code, message string, line uint32) *pb.DatabaseQueryResultChunk {
	return &pb.DatabaseQueryResultChunk{
		Body: &pb.DatabaseQueryResultChunk_Error{Error: &pb.DatabaseQueryError{
			Code:    code,
			Message: message,
			Line:    line,
		}},
	}
}

// emitChunk serializes chunk as protojson + '\n' (NDJSON) and pushes it
// through the agent's emit callback.
func emitChunk(emit func(string), chunk *pb.DatabaseQueryResultChunk) error {
	b, err := protojson.Marshal(chunk)
	if err != nil {
		return fmt.Errorf("marshal chunk: %w", err)
	}
	emit(string(b) + "\n")
	return nil
}

// maxInt64 is a tiny generic-free max so we don't depend on go 1.21+
// builtins inside this PR. Avoids importing math for one comparison.
func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
