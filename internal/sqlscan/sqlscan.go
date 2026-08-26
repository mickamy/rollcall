// Package sqlscan classifies SQL statements well enough to support a read-only
// policy. It is a lexical classifier, not a parser: it tokenizes far enough to
// skip strings, comments, dollar-quoted bodies, and quoted identifiers so that
// keywords inside them are never mistaken for commands, then classifies each
// top-level statement by its leading keyword.
//
// It cannot see writes performed through functions (for example nextval or a
// volatile user function), so it is one layer of a read-only defense whose
// guarantee comes from the server-side read-only transaction mode.
package sqlscan

type Kind int

const (
	Unknown Kind = iota
	Empty
	Select
	Cursor // DECLARE/FETCH/MOVE/CLOSE, SHOW, and other read-only reads
	Set    // SET/RESET
	Tx     // BEGIN/COMMIT/ROLLBACK/SAVEPOINT
	Explain
	CopyTo // COPY ... TO STDOUT
	Insert
	Update
	Delete
	Merge
	Truncate
	SelectInto
	CopyFrom
	CopyExternal // COPY ... TO a file or program
	Call
	DDL
)

func (k Kind) String() string {
	switch k {
	case Unknown:
		return "unknown statement"
	case Empty:
		return "empty statement"
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
		return "COPY TO STDOUT"
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
	case SelectInto:
		return "SELECT INTO"
	case CopyFrom:
		return "COPY FROM"
	case CopyExternal:
		return "COPY TO a file or program"
	case Call:
		return "CALL"
	case DDL:
		return "DDL"
	}

	return "unknown statement"
}

// Mutating reports whether a statement of this kind can change data or schema.
// Unknown is treated as mutating so an unrecognized statement fails closed.
func (k Kind) Mutating() bool {
	switch k {
	case Insert, Update, Delete, Merge, Truncate, SelectInto, CopyFrom, CopyExternal, Call, DDL, Unknown:
		return true
	case Empty, Select, Cursor, Set, Tx, Explain, CopyTo:
		return false
	}

	return true
}

// Finding describes one top-level statement.
type Finding struct {
	Kind Kind
	// DisablesReadOnly is true when the statement could return the connection to
	// read-write, for example SET default_transaction_read_only = off or
	// BEGIN ... READ WRITE. Such statements must be refused on a read-only
	// connection or the server-side read-only mode can be turned off.
	DisablesReadOnly bool
}

// Scan classifies each top-level statement in sql.
func Scan(sql string) []Finding {
	stmts := tokenize(sql)
	out := make([]Finding, 0, len(stmts))
	for _, toks := range stmts {
		out = append(out, Finding{Kind: classify(toks), DisablesReadOnly: disablesReadOnly(toks)})
	}
	if len(out) == 0 {
		return []Finding{{Kind: Empty}}
	}

	return out
}

// Classify returns the kind of each top-level statement in sql.
func Classify(sql string) []Kind {
	findings := Scan(sql)
	kinds := make([]Kind, len(findings))
	for i, f := range findings {
		kinds[i] = f.Kind
	}

	return kinds
}

// Mutating reports whether any statement in sql can change data or schema.
func Mutating(sql string) bool {
	for _, f := range Scan(sql) {
		if f.Kind.Mutating() {
			return true
		}
	}

	return false
}

func classify(toks []token) Kind {
	w, i := firstWord(toks)
	if i < 0 {
		return Empty
	}

	switch w {
	case "SELECT", "VALUES", "TABLE":
		return selectOrInto(toks)
	case "SHOW", "DECLARE", "FETCH", "MOVE", "CLOSE", "LISTEN", "UNLISTEN", "DISCARD",
		"PREPARE", "DEALLOCATE", "EXECUTE", "NOTIFY", "CHECKPOINT":
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
		return classifyCopy(toks)
	case "WITH":
		return classifyWith(toks)
	case "EXPLAIN":
		return classifyExplain(toks)
	case "CREATE", "ALTER", "DROP", "GRANT", "REVOKE", "COMMENT",
		"REINDEX", "CLUSTER", "VACUUM", "ANALYZE", "REFRESH", "IMPORT", "LOAD", "SECURITY", "LOCK":
		return DDL
	}

	return Unknown
}

// selectOrInto classifies a SELECT, upgrading it to SelectInto when a top-level
// INTO creates a table.
func selectOrInto(toks []token) Kind {
	if hasWordAtTopLevel(toks, "INTO") {
		return SelectInto
	}

	return Select
}

// classifyCopy finds the first FROM or TO at the top level. COPY ... FROM writes
// a table; COPY ... TO STDOUT reads; COPY ... TO a file or program writes on the
// server, so only TO STDOUT is treated as a read.
func classifyCopy(toks []token) Kind {
	depth := 0
	for i := 1; i < len(toks); i++ {
		switch toks[i].kind {
		case kindOpen:
			depth++
		case kindClose:
			depth--
		case kindWord:
			if depth != 0 {
				continue
			}
			switch toks[i].text {
			case "FROM":
				return CopyFrom
			case "TO":
				if nextWord(toks, i) == "STDOUT" {
					return CopyTo
				}

				return CopyExternal
			}
		case kindIdent:
		}
	}

	return CopyFrom // no clear direction: assume the writing form
}

// classifyWith treats a WITH statement as mutating if any data-modifying command
// appears in it, since a CTE such as WITH d AS (DELETE ...) executes.
func classifyWith(toks []token) Kind {
	for _, t := range toks[1:] {
		if t.kind != kindWord {
			continue
		}
		switch t.text {
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

	return selectOrInto(toks)
}

// classifyExplain returns EXPLAIN unless the plan runs with ANALYZE, which
// executes the underlying statement; then it classifies that statement.
func classifyExplain(toks []token) Kind {
	if !containsWord(toks, "ANALYZE") {
		return Explain // without ANALYZE the underlying statement never runs
	}

	for i := 1; i < len(toks); i++ {
		if toks[i].kind != kindWord {
			continue
		}
		if isExplainOption(toks[i].text) {
			continue
		}

		return classify(toks[i:])
	}

	return Explain
}

func isExplainOption(w string) bool {
	switch w {
	case "ANALYZE", "VERBOSE", "COSTS", "SETTINGS", "GENERIC_PLAN", "BUFFERS", "WAL",
		"TIMING", "SUMMARY", "MEMORY", "SERIALIZE", "FORMAT",
		"ON", "OFF", "TRUE", "FALSE", "TEXT", "JSON", "XML", "YAML", "NONE":
		return true
	}

	return false
}

// disablesReadOnly reports whether the statement could turn off read-only mode.
func disablesReadOnly(toks []token) bool {
	w, _ := firstWord(toks)
	switch w {
	case "SET", "RESET", "BEGIN", "START", "SELECT", "WITH":
	default:
		return false
	}

	for i, t := range toks {
		// READ WRITE, as in SET TRANSACTION READ WRITE or BEGIN ... READ WRITE.
		if t.kind == kindWord && t.text == "READ" && nextWord(toks, i) == "WRITE" {
			return true
		}
		// Any reference to the read-only GUCs, quoted or not.
		if folds(t, "default_transaction_read_only") || folds(t, "transaction_read_only") {
			return true
		}
		// set_config('...transaction_read_only', ...) reached through SELECT.
		if t.kind == kindWord && t.text == "SET_CONFIG" {
			return true
		}
		// RESET ALL clears every session setting, including read-only mode.
		if t.kind == kindWord && t.text == "RESET" && nextWord(toks, i) == "ALL" {
			return true
		}
	}

	return false
}

func folds(t token, name string) bool {
	switch t.kind {
	case kindWord:
		return t.text == upper(name)
	case kindIdent:
		return t.text == name
	case kindOpen, kindClose:
		return false
	}

	return false
}

func firstWord(toks []token) (string, int) {
	for i, t := range toks {
		if t.kind == kindWord {
			return t.text, i
		}
	}

	return "", -1
}

func nextWord(toks []token, i int) string {
	for j := i + 1; j < len(toks); j++ {
		if toks[j].kind == kindWord {
			return toks[j].text
		}
	}

	return ""
}

func containsWord(toks []token, w string) bool {
	for _, t := range toks {
		if t.kind == kindWord && t.text == w {
			return true
		}
	}

	return false
}

func hasWordAtTopLevel(toks []token, w string) bool {
	depth := 0
	for _, t := range toks {
		switch t.kind {
		case kindOpen:
			depth++
		case kindClose:
			depth--
		case kindWord:
			if depth == 0 && t.text == w {
				return true
			}
		case kindIdent:
		}
	}

	return false
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}

	return string(b)
}
