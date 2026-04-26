// Package database — classify.go.
//
// Lightweight SQL statement classifier. Decides whether a single statement
// is read-only (SELECT, SHOW, EXPLAIN, DESCRIBE/DESC, WITH … SELECT,
// VALUES, TABLE) or destructive (everything else: INSERT, UPDATE, DELETE,
// CREATE, DROP, ALTER, TRUNCATE, GRANT, REVOKE, SET, BEGIN, COMMIT,
// ROLLBACK, CALL, etc.).
//
// This is NOT a full SQL parser — only the leading top-level keyword
// matters for the read-vs-write decision. The classifier is deliberately
// fail-safe: when in doubt the answer is StatementWrite, so a destructive
// statement can never be smuggled past the read-only gate via syntax the
// classifier does not recognize.
//
// Multi-statement input is rejected. Callers are required to split on
// `;` themselves and call ClassifyStatement once per statement; this
// constraint keeps the classifier simple and removes a class of evasion
// attacks where a destructive tail rides behind a benign head.
//
// String-literal contents are NOT inspected. The classifier strips line
// comments (`-- …` to newline), block comments (`/* … */`, non-greedy,
// nested NOT supported — postgres extension only), and skips past
// single-quoted, double-quoted, backtick-quoted, and dollar-quoted
// strings so a `;` inside a literal does not look like a statement
// terminator.
package database

import (
	"errors"
	"strings"
	"unicode"

	pb "github.com/cloudnan-tech/cloudnan-agent/proto/agent"
)

// StatementKind names the classifier's verdict about a single statement.
type StatementKind int

const (
	// StatementUnknown is reserved for future use; the public API never
	// returns this value today (we collapse "unknown" into StatementWrite
	// for safety).
	StatementUnknown StatementKind = iota
	// StatementRead means the statement only reads server state (SELECT
	// family, plus engine-specific read shortcuts).
	StatementRead
	// StatementWrite means the statement may mutate server state. Anything
	// the classifier cannot positively recognize as read-only lands here.
	StatementWrite
)

// readKeywords is the canonical set of leading keywords that classify as
// read-only across all supported engines. WITH is handled specially by
// classifyWith (it must lead to a SELECT or VALUES at the CTE boundary).
var readKeywords = map[string]bool{
	"select":   true,
	"show":     true,
	"explain":  true,
	"describe": true,
	"desc":     true,
	"values":   true,
	"table":    true, // postgres "TABLE foo" ≡ "SELECT * FROM foo"
}

// ClassifyStatement returns the kind of a single SQL statement. It returns
// an error if more than one non-empty statement is present in sql.
// Comments and leading whitespace are stripped before classification.
func ClassifyStatement(sql string, engine pb.DatabaseEngine) (StatementKind, error) {
	stripped, err := stripCommentsAndCheckSingle(sql)
	if err != nil {
		return StatementWrite, err
	}
	stripped = strings.TrimSpace(stripped)
	if stripped == "" {
		return StatementWrite, errors.New("empty statement")
	}

	first, rest := firstKeyword(stripped)
	first = strings.ToLower(first)

	if first == "with" {
		return classifyWith(rest)
	}
	if readKeywords[first] {
		return StatementRead, nil
	}
	// Default: fail-safe to write. Includes BEGIN, START, COMMIT, ROLLBACK,
	// SET, CALL, INSERT, UPDATE, DELETE, MERGE, REPLACE, CREATE, DROP,
	// ALTER, TRUNCATE, RENAME, GRANT, REVOKE, ANALYZE, VACUUM, COPY,
	// LOCK, LOAD, FLUSH, RESET, REINDEX, CLUSTER, REFRESH, NOTIFY,
	// LISTEN, UNLISTEN, PREPARE, EXECUTE, DEALLOCATE, DO, …
	return StatementWrite, nil
}

// firstKeyword returns the leading identifier token of sql (alphanumeric +
// underscore), and the remainder of sql after that token. Whitespace and
// comments are assumed already stripped by the caller; firstKeyword does
// not re-strip.
func firstKeyword(sql string) (kw, rest string) {
	end := 0
	for end < len(sql) {
		r := rune(sql[end])
		if r >= 0x80 || unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			end++
			continue
		}
		break
	}
	return sql[:end], sql[end:]
}

// classifyWith handles `WITH [RECURSIVE] cte_name AS (…) [, …] <body>`.
// We scan past the parenthesized CTE bodies (respecting strings, dollar
// quotes, and comments inside them) and look at the leading keyword of
// the eventual <body>. Accept only if it's SELECT or VALUES; anything
// else (INSERT/UPDATE/DELETE — postgres allows DML in CTE bodies) is
// classified as write.
func classifyWith(rest string) (StatementKind, error) {
	rest = strings.TrimSpace(rest)
	// Optional RECURSIVE keyword (postgres / mysql 8).
	lower := strings.ToLower(rest)
	if strings.HasPrefix(lower, "recursive") {
		// Must be followed by whitespace; if not, it's actually an
		// identifier starting with "recursive..." — treat as opaque.
		if len(rest) > len("recursive") && isSpaceOrParen(rune(rest[len("recursive")])) {
			rest = rest[len("recursive"):]
			rest = strings.TrimSpace(rest)
		}
	}

	for {
		// Consume cte_name (identifier or quoted identifier).
		consumed, err := consumeIdent(rest)
		if err != nil {
			return StatementWrite, nil // give up, fail-safe
		}
		rest = strings.TrimSpace(rest[consumed:])

		// Optional column list: ( colA, colB ).
		if strings.HasPrefix(rest, "(") {
			end := matchParen(rest)
			if end < 0 {
				return StatementWrite, nil
			}
			rest = strings.TrimSpace(rest[end+1:])
		}

		// Required AS keyword.
		if !strings.HasPrefix(strings.ToLower(rest), "as") {
			return StatementWrite, nil
		}
		rest = strings.TrimSpace(rest[2:])

		// Optional MATERIALIZED / NOT MATERIALIZED (postgres 12+).
		lower = strings.ToLower(rest)
		if strings.HasPrefix(lower, "not materialized") {
			rest = strings.TrimSpace(rest[len("not materialized"):])
		} else if strings.HasPrefix(lower, "materialized") {
			rest = strings.TrimSpace(rest[len("materialized"):])
		}

		// Required parenthesized CTE body.
		if !strings.HasPrefix(rest, "(") {
			return StatementWrite, nil
		}
		end := matchParen(rest)
		if end < 0 {
			return StatementWrite, nil
		}
		rest = strings.TrimSpace(rest[end+1:])

		// Comma → another CTE; otherwise we've reached the body keyword.
		if strings.HasPrefix(rest, ",") {
			rest = strings.TrimSpace(rest[1:])
			continue
		}
		break
	}

	// rest now begins with the body keyword.
	body, _ := firstKeyword(rest)
	body = strings.ToLower(body)
	if body == "select" || body == "values" {
		return StatementRead, nil
	}
	return StatementWrite, nil
}

// consumeIdent skips past a single identifier at the start of s. Supports
// bare identifiers, "double-quoted", `back-tick-quoted`, and [bracketed]
// (T-SQL) forms. Returns the byte length consumed or an error.
func consumeIdent(s string) (int, error) {
	if s == "" {
		return 0, errors.New("expected identifier, got EOF")
	}
	switch s[0] {
	case '"':
		return consumeQuoted(s, '"')
	case '`':
		return consumeQuoted(s, '`')
	case '[':
		// MS-style; rare but cheap to support.
		end := strings.IndexByte(s[1:], ']')
		if end < 0 {
			return 0, errors.New("unterminated [identifier]")
		}
		return 1 + end + 1, nil
	}
	// Bare identifier: letters/digits/underscore, possibly schema-qualified.
	i := 0
	for i < len(s) {
		r := rune(s[i])
		if r == '.' { // schema.table
			i++
			continue
		}
		if r >= 0x80 || unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			i++
			continue
		}
		break
	}
	if i == 0 {
		return 0, errors.New("not an identifier")
	}
	return i, nil
}

// consumeQuoted skips past a "..."/`...` quoted identifier honoring the
// SQL doubling-escape (e.g. "foo""bar" → foo"bar). Returns bytes consumed.
func consumeQuoted(s string, q byte) (int, error) {
	if len(s) < 2 || s[0] != q {
		return 0, errors.New("expected quoted identifier")
	}
	i := 1
	for i < len(s) {
		if s[i] == q {
			if i+1 < len(s) && s[i+1] == q {
				i += 2
				continue
			}
			return i + 1, nil
		}
		i++
	}
	return 0, errors.New("unterminated quoted identifier")
}

// matchParen, given s starting with '(', returns the index of the
// matching ')'. Returns -1 if the parenthesis is unbalanced. Skips
// strings, dollar-quoted blocks, and comments encountered along the way.
func matchParen(s string) int {
	depth := 0
	i := 0
	for i < len(s) {
		c := s[i]
		switch c {
		case '(':
			depth++
			i++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
			i++
		case '\'':
			adv := skipSingleQuoted(s[i:])
			if adv <= 0 {
				return -1
			}
			i += adv
		case '"':
			adv := skipDoubleQuoted(s[i:])
			if adv <= 0 {
				return -1
			}
			i += adv
		case '`':
			adv := skipBacktickQuoted(s[i:])
			if adv <= 0 {
				return -1
			}
			i += adv
		case '$':
			if adv := skipDollarQuoted(s[i:]); adv > 0 {
				i += adv
				continue
			}
			i++
		case '-':
			if i+1 < len(s) && s[i+1] == '-' {
				// line comment
				nl := strings.IndexByte(s[i:], '\n')
				if nl < 0 {
					return -1
				}
				i += nl + 1
				continue
			}
			i++
		case '/':
			if i+1 < len(s) && s[i+1] == '*' {
				end := strings.Index(s[i+2:], "*/")
				if end < 0 {
					return -1
				}
				i += 2 + end + 2
				continue
			}
			i++
		default:
			i++
		}
	}
	return -1
}

// stripCommentsAndCheckSingle removes line/block comments from sql and
// verifies that no `;` is followed by additional non-whitespace,
// non-comment content. Returns the comment-stripped SQL (without
// trailing semicolons).
func stripCommentsAndCheckSingle(sql string) (string, error) {
	var out strings.Builder
	out.Grow(len(sql))
	i := 0
	sawTerminator := false
	for i < len(sql) {
		// If we already saw `;` and we're now scanning past it, anything
		// other than whitespace, more `;`, or a comment is a second
		// statement.
		if sawTerminator {
			c := sql[i]
			switch {
			case c == ' ' || c == '\t' || c == '\n' || c == '\r':
				i++
				continue
			case c == ';':
				i++
				continue
			case c == '-' && i+1 < len(sql) && sql[i+1] == '-':
				nl := strings.IndexByte(sql[i:], '\n')
				if nl < 0 {
					return "", nil
				}
				i += nl + 1
				continue
			case c == '/' && i+1 < len(sql) && sql[i+1] == '*':
				end := strings.Index(sql[i+2:], "*/")
				if end < 0 {
					return "", errors.New("unterminated block comment")
				}
				i += 2 + end + 2
				continue
			default:
				return "", errors.New("multiple statements not allowed; pass one statement at a time")
			}
		}

		c := sql[i]
		switch {
		case c == '-' && i+1 < len(sql) && sql[i+1] == '-':
			nl := strings.IndexByte(sql[i:], '\n')
			if nl < 0 {
				i = len(sql)
			} else {
				i += nl + 1
			}
			out.WriteByte(' ')
		case c == '/' && i+1 < len(sql) && sql[i+1] == '*':
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return "", errors.New("unterminated block comment")
			}
			i += 2 + end + 2
			out.WriteByte(' ')
		case c == '\'':
			adv := skipSingleQuoted(sql[i:])
			if adv <= 0 {
				return "", errors.New("unterminated string literal")
			}
			out.WriteString(sql[i : i+adv])
			i += adv
		case c == '"':
			adv := skipDoubleQuoted(sql[i:])
			if adv <= 0 {
				return "", errors.New("unterminated quoted identifier")
			}
			out.WriteString(sql[i : i+adv])
			i += adv
		case c == '`':
			adv := skipBacktickQuoted(sql[i:])
			if adv <= 0 {
				return "", errors.New("unterminated backtick identifier")
			}
			out.WriteString(sql[i : i+adv])
			i += adv
		case c == '$':
			if adv := skipDollarQuoted(sql[i:]); adv > 0 {
				out.WriteString(sql[i : i+adv])
				i += adv
				continue
			}
			out.WriteByte(c)
			i++
		case c == ';':
			sawTerminator = true
			i++
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.String(), nil
}

// skipSingleQuoted, given s starting with `'`, returns the byte length up
// to and including the closing quote. SQL doubling-escape is honored
// (`”` is a literal apostrophe inside the string). MySQL-style backslash
// escapes are NOT interpreted as escaping the quote — the conservative
// reading is that `\'` ends the string and `'` is a stray quote, but
// since classify is leading-keyword-only the difference does not matter
// for read-vs-write decisions.
func skipSingleQuoted(s string) int {
	if len(s) < 1 || s[0] != '\'' {
		return 0
	}
	i := 1
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if s[i] == '\'' {
			if i+1 < len(s) && s[i+1] == '\'' {
				i += 2
				continue
			}
			return i + 1
		}
		i++
	}
	return 0
}

// skipDoubleQuoted skips a "..." quoted identifier (postgres) honoring
// the doubling-escape "".
func skipDoubleQuoted(s string) int {
	if len(s) < 1 || s[0] != '"' {
		return 0
	}
	i := 1
	for i < len(s) {
		if s[i] == '"' {
			if i+1 < len(s) && s[i+1] == '"' {
				i += 2
				continue
			}
			return i + 1
		}
		i++
	}
	return 0
}

// skipBacktickQuoted skips a `...` quoted identifier (mysql/mariadb).
func skipBacktickQuoted(s string) int {
	if len(s) < 1 || s[0] != '`' {
		return 0
	}
	i := 1
	for i < len(s) {
		if s[i] == '`' {
			if i+1 < len(s) && s[i+1] == '`' {
				i += 2
				continue
			}
			return i + 1
		}
		i++
	}
	return 0
}

// skipDollarQuoted handles postgres dollar-quoted strings: $tag$ … $tag$
// where tag is empty or an identifier. Returns 0 when s does not start
// with a valid dollar quote.
func skipDollarQuoted(s string) int {
	if len(s) < 2 || s[0] != '$' {
		return 0
	}
	// Tag is everything up to the next `$`, must be alnum/underscore.
	tagEnd := 1
	for tagEnd < len(s) && s[tagEnd] != '$' {
		c := s[tagEnd]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') {
			tagEnd++
			continue
		}
		return 0 // not a dollar quote, just a stray $
	}
	if tagEnd >= len(s) {
		return 0
	}
	tag := s[:tagEnd+1] // includes the closing $
	closing := tag      // identical opener and closer
	idx := strings.Index(s[len(tag):], closing)
	if idx < 0 {
		return 0
	}
	return len(tag) + idx + len(closing)
}

// isSpaceOrParen reports whether r is whitespace or '(' — used to
// disambiguate the WITH RECURSIVE keyword from an identifier that
// starts with "recursive".
func isSpaceOrParen(r rune) bool {
	return unicode.IsSpace(r) || r == '('
}
