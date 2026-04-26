package database

import (
	"context"
	"fmt"
)

// Handler dispatches COMMAND_TYPE_DATABASE operations. PR 1 ships the
// routing scaffold; engine-specific logic (mysql, postgresql) lands in PR 2.
type Handler struct {
	// Future: vault *credstore.Store, drivers map[pb.DatabaseEngine]Driver
}

// NewHandler constructs a Handler with no driver wiring. PR 2 will inject
// the credential vault and engine drivers here.
func NewHandler() *Handler {
	return &Handler{}
}

// Result is what the agent dispatcher returns up to executeCommand.
// Stdout/Stderr are placed verbatim into the final CommandResponse fields.
type Result struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// Execute is the unary entry point. For ops that stream (exec_query,
// export_dump) callers should use ExecuteStreaming instead — calling
// Execute on a streaming op returns an error result.
func (h *Handler) Execute(ctx context.Context, args []string) *Result {
	if len(args) < 1 {
		return errResult("database command requires operation name in args[0]")
	}
	op := args[0]
	switch op {
	case "discover", "connect", "disconnect", "ping",
		"list_dbs", "list_users",
		"create_db", "drop_db", "create_user", "grant", "drop_user":
		return errResult(fmt.Sprintf("database op %q not implemented (planned for PR 2)", op))
	case "exec_query", "export_dump":
		return errResult(fmt.Sprintf("database op %q is streaming; caller must use ExecuteStreaming", op))
	default:
		return errResult(fmt.Sprintf("unknown database op %q", op))
	}
}

// ExecuteStreaming handles streaming ops. emit is called once per chunk;
// the agent transport is responsible for wrapping each chunk into a
// CommandResponse with Status=RUNNING and pushing it on the bidi stream.
// Returns the final result; transport sends it as Status=COMPLETED (or FAILED).
func (h *Handler) ExecuteStreaming(
	ctx context.Context,
	args []string,
	emit func(stdoutChunk string),
) *Result {
	if len(args) < 1 {
		return errResult("database command requires operation name in args[0]")
	}
	op := args[0]
	switch op {
	case "exec_query", "export_dump":
		return errResult(fmt.Sprintf("database op %q not implemented (planned for PR 2)", op))
	default:
		return errResult(fmt.Sprintf("op %q is not streaming or is unknown", op))
	}
}

// IsStreamingOp reports whether the named op uses streaming chunks.
func IsStreamingOp(op string) bool {
	return op == "exec_query" || op == "export_dump"
}

func errResult(msg string) *Result {
	return &Result{ExitCode: 1, Stderr: msg}
}
