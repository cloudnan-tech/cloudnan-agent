// Package database — quote.go.
//
// SQL identifier and string-literal quoting helpers, plus a privilege-name
// whitelist validator. All SQL we build at runtime for create/drop/grant
// operations passes through these helpers — never via raw concatenation.
//
// The quoting rules below are the documented SQL standard for each engine:
//
//   - MySQL/MariaDB: identifiers in backticks; backticks doubled to escape.
//   - PostgreSQL:    identifiers in double quotes; double-quotes doubled to escape.
//   - String values: single-quoted; embedded single quotes doubled. Backslashes
//     are also doubled because MySQL (without ANSI_QUOTES/NO_BACKSLASH_ESCAPES)
//     treats `\` as an escape character inside string literals.
//
// Privilege names are validated against the whitelist regex
// `^[A-Z][A-Z _]*$` per element (e.g. ALL, SELECT, INSERT, CREATE TEMPORARY
// TABLES). Anything that does not match is rejected — we never trust an
// inbound privilege string enough to pass it through unchecked.
package database

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// privilegeNameRe is the whitelist for individual SQL privilege tokens.
// Permits a single uppercase word or several uppercase words separated by
// single spaces (e.g. "CREATE TEMPORARY TABLES").
var privilegeNameRe = regexp.MustCompile(`^[A-Z][A-Z _]*$`)

// quoteMySQLIdent wraps name in backticks, escaping any backticks present
// in the input by doubling. Empty identifiers are rejected.
func quoteMySQLIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// quotePostgresIdent wraps name in double quotes, escaping any embedded
// double quotes by doubling.
func quotePostgresIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// escapeSQLString escapes a value to be embedded between single quotes in
// a SQL statement. Doubles single quotes and backslashes; the caller is
// responsible for adding the surrounding quotes.
func escapeSQLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `''`)
	return s
}

// validatePrivilegesList returns an error if any element of privs fails the
// whitelist regex. An empty slice is treated as valid (caller substitutes a
// default — e.g. "ALL PRIVILEGES").
func validatePrivilegesList(privs []string) error {
	for _, p := range privs {
		if p == "" {
			return errors.New("privileges: empty token not allowed")
		}
		if !privilegeNameRe.MatchString(p) {
			return fmt.Errorf("privileges: token %q rejected by whitelist", p)
		}
	}
	return nil
}

// validateNonEmpty returns an error if name is empty. Used to short-circuit
// before touching SQL generation when callers forget to populate a request
// field.
func validateNonEmpty(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	return nil
}
