// Package database — cell_encode.go.
//
// Result-set cell encoding for streaming query output. Every cell on the
// wire is a UTF-8 byte slice, and NULL is signaled by a parallel
// is_null[i]=true flag rather than by an empty cells[i]. This lets the
// frontend distinguish "" from NULL without burning a sentinel value or
// engine-specific quoting.
//
// We scan rows into *sql.RawBytes pointers so binary columns (BLOB,
// bytea) survive intact — they are then promoted to UTF-8 if the bytes
// already are valid UTF-8, otherwise serialized as `0x<hex>` so the user
// sees a stable, copy-pasteable representation. This matches what
// MySQL's CLI prints for non-text columns and what psql prints for bytea
// in escape format, while keeping the wire format JSON-friendly.
package database

import (
	"database/sql"
	"encoding/hex"
	"unicode/utf8"
)

// scanRow scans the next row of rs into per-column cell bytes and a
// parallel is_null slice. The returned cells slice owns its own storage
// (decoupled from the driver's RawBytes buffer), so the caller may keep
// references across subsequent rows.Next() calls without worrying about
// the driver reusing buffers.
func scanRow(rs *sql.Rows, columnCount int) (cells [][]byte, isNull []bool, err error) {
	raws := make([]sql.RawBytes, columnCount)
	args := make([]interface{}, columnCount)
	for i := range raws {
		args[i] = &raws[i]
	}
	if err := rs.Scan(args...); err != nil {
		return nil, nil, err
	}
	cells = make([][]byte, columnCount)
	isNull = make([]bool, columnCount)
	for i, rb := range raws {
		if rb == nil {
			isNull[i] = true
			cells[i] = nil
			continue
		}
		cells[i] = encodeCell(rb)
	}
	return cells, isNull, nil
}

// encodeCell promotes a raw byte slice to a UTF-8 representation. If the
// input is already valid UTF-8, it is copied as-is; otherwise the bytes
// are rendered as `0x<lowercase-hex>` so the result is always JSON-safe.
func encodeCell(rb sql.RawBytes) []byte {
	if utf8.Valid(rb) {
		out := make([]byte, len(rb))
		copy(out, rb)
		return out
	}
	const prefix = "0x"
	out := make([]byte, len(prefix)+hex.EncodedLen(len(rb)))
	copy(out, prefix)
	hex.Encode(out[len(prefix):], rb)
	return out
}
