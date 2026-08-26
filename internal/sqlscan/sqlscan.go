// Package sqlscan classifies SQL statements well enough to enforce a read-only
// policy. It is a lexical classifier, not a parser: it tokenizes far enough to
// skip strings, comments, dollar-quoted bodies, and quoted identifiers so that
// keywords inside them are never mistaken for commands, then classifies each
// top-level statement by its leading keyword.
package sqlscan

import "slices"

type Kind int

const (
	Unknown Kind = iota
	Empty
	Select
	Cursor // DECLARE/FETCH/MOVE/CLOSE, SHOW, and other read-only reads
	Set    // SET/RESET
	Tx     // BEGIN/COMMIT/ROLLBACK/SAVEPOINT
	Explain
	CopyTo
	Insert
	Update
	Delete
	Merge
	Truncate
	CopyFrom
	Call
	DDL
)

func (k Kind) String() string {
	switch k {
	case Unknown:
		return "unknown statement"
	case Empty:
		return "empty"
	case Select:
		return "SELECT"
	case Cursor:
		return "cursor operation"
	case Set:
		return "SET"
	case Tx:
		return "transaction control"
	case Explain:
		return "EXPLAIN"
	case CopyTo:
		return "COPY TO"
	case Insert:
		return "INSERT"
	case Update:
		return "UPDATE"
	case Delete:
		return "DELETE"
	case Merge:
		return "MERGE"
	case Truncate:
		return "TRUNCATE"
	case CopyFrom:
		return "COPY FROM"
	case Call:
		return "CALL"
	case DDL:
		return "DDL"
	}

	return "unknown statement"
}

// Mutating reports whether a statement of this kind can change data or schema.
// Unknown is treated as mutating so an unrecognized statement fails closed under
// a read-only policy.
func (k Kind) Mutating() bool {
	switch k {
	case Insert, Update, Delete, Merge, Truncate, CopyFrom, Call, DDL, Unknown:
		return true
	case Empty, Select, Cursor, Set, Tx, Explain, CopyTo:
		return false
	}

	return true
}

// Classify returns the kind of each top-level statement in sql. Empty input, or
// input that is only comments and whitespace, yields a single Empty.
func Classify(sql string) []Kind {
	kinds := make([]Kind, 0, 1)
	for _, words := range statements(sql) {
		kinds = append(kinds, classify(words))
	}
	if len(kinds) == 0 {
		return []Kind{Empty}
	}

	return kinds
}

// Mutating reports whether any statement in sql can change data or schema.
func Mutating(sql string) bool {
	for _, k := range Classify(sql) {
		if k.Mutating() {
			return true
		}
	}

	return false
}

func classify(words []string) Kind {
	if len(words) == 0 {
		return Empty
	}

	switch words[0] {
	case "SELECT", "VALUES", "TABLE":
		return Select
	case "SHOW", "DECLARE", "FETCH", "MOVE", "CLOSE", "LISTEN", "UNLISTEN", "DISCARD":
		return Cursor
	case "SET", "RESET":
		return Set
	case "BEGIN", "START", "COMMIT", "END", "ROLLBACK", "SAVEPOINT", "RELEASE", "ABORT":
		return Tx
	case "INSERT":
		return Insert
	case "UPDATE":
		return Update
	case "DELETE":
		return Delete
	case "MERGE":
		return Merge
	case "TRUNCATE":
		return Truncate
	case "CALL", "DO":
		return Call
	case "COPY":
		return classifyCopy(words)
	case "WITH":
		return classifyWith(words)
	case "EXPLAIN":
		return classifyExplain(words)
	case "CREATE", "ALTER", "DROP", "GRANT", "REVOKE", "COMMENT",
		"REINDEX", "CLUSTER", "VACUUM", "ANALYZE", "REFRESH", "IMPORT",
		"CHECKPOINT", "LOAD", "SECURITY", "LOCK":
		return DDL
	default:
		return Unknown
	}
}

// classifyCopy distinguishes COPY ... FROM (a write) from COPY ... TO and the
// COPY (query) TO form (both reads).
func classifyCopy(words []string) Kind {
	for _, w := range words[1:] {
		if w == "SELECT" || w == "WITH" || w == "VALUES" {
			return CopyTo // only the query form, which is always TO
		}
	}
	for _, w := range words[1:] {
		switch w {
		case "FROM":
			return CopyFrom
		case "TO":
			return CopyTo
		}
	}

	return CopyFrom // no clear direction: assume the writing form
}

// classifyWith treats a WITH statement as mutating if any data-modifying command
// appears anywhere in it, since a CTE such as WITH d AS (DELETE ...) executes.
func classifyWith(words []string) Kind {
	for _, w := range words[1:] {
		switch w {
		case "INSERT":
			return Insert
		case "UPDATE":
			return Update
		case "DELETE":
			return Delete
		case "MERGE":
			return Merge
		}
	}

	return Select
}

// classifyExplain returns EXPLAIN unless the plan is run with ANALYZE, which
// executes the underlying statement; then it classifies that statement.
func classifyExplain(words []string) Kind {
	if !slices.Contains(words[1:], "ANALYZE") {
		return Explain
	}

	for _, w := range words[1:] {
		switch w {
		case "SELECT", "VALUES", "TABLE":
			return Select
		case "INSERT":
			return Insert
		case "UPDATE":
			return Update
		case "DELETE":
			return Delete
		case "MERGE":
			return Merge
		case "WITH":
			return classifyWith(words)
		}
	}

	return Explain
}
