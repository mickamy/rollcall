package sqlscan

import "strings"

// statements splits sql into top-level statements, each a slice of the
// uppercased unquoted words it contains. Strings, comments, dollar-quoted
// bodies, and quoted identifiers are skipped so their contents never look like
// keywords; numbers and punctuation are dropped.
func statements(sql string) [][]string {
	var stmts [][]string
	cur := make([]string, 0, 8)
	i, n := 0, len(sql)

	for i < n {
		c := sql[i]
		switch {
		case isSpace(c):
			i++
		case c == '-' && i+1 < n && sql[i+1] == '-':
			i = skipLineComment(sql, i+2)
		case c == '/' && i+1 < n && sql[i+1] == '*':
			i = skipBlockComment(sql, i+2)
		case c == '\'':
			i = skipQuoted(sql, i+1, '\'')
		case c == '"':
			i = skipQuoted(sql, i+1, '"')
		case c == '$':
			if end, ok := skipDollarQuote(sql, i); ok {
				i = end
			} else {
				i = skipWord(sql, i+1) // parameter such as $1
			}
		case c == ';':
			stmts = append(stmts, cur)
			cur = make([]string, 0, 8)
			i++
		case isWordStart(c):
			j := skipWord(sql, i+1)
			cur = append(cur, strings.ToUpper(sql[i:j]))
			i = j
		default:
			i++
		}
	}
	stmts = append(stmts, cur)

	return stmts
}

func skipLineComment(s string, i int) int {
	for i < len(s) && s[i] != '\n' {
		i++
	}

	return i
}

func skipBlockComment(s string, i int) int {
	depth := 1
	for i < len(s) && depth > 0 {
		switch {
		case i+1 < len(s) && s[i] == '/' && s[i+1] == '*':
			depth++
			i += 2
		case i+1 < len(s) && s[i] == '*' && s[i+1] == '/':
			depth--
			i += 2
		default:
			i++
		}
	}

	return i
}

// skipQuoted skips a string literal or quoted identifier that has already had
// its opening quote consumed, honoring the doubled-quote escape.
func skipQuoted(s string, i int, quote byte) int {
	for i < len(s) {
		if s[i] == quote {
			if i+1 < len(s) && s[i+1] == quote {
				i += 2

				continue
			}

			return i + 1
		}
		i++
	}

	return i
}

// skipDollarQuote skips a $tag$...$tag$ body. It reports false when the dollar
// does not open a valid tag (for example a $1 parameter), leaving it to the
// caller.
func skipDollarQuote(s string, i int) (int, bool) {
	j := i + 1
	for j < len(s) && isTagPart(s[j]) {
		j++
	}
	if j >= len(s) || s[j] != '$' {
		return 0, false
	}
	if j > i+1 && isDigit(s[i+1]) {
		return 0, false // tags do not start with a digit; this is a parameter
	}

	tag := s[i : j+1]
	rest := s[j+1:]
	if k := strings.Index(rest, tag); k >= 0 {
		return j + 1 + k + len(tag), true
	}

	return len(s), true // unterminated: consume the remainder
}

func skipWord(s string, i int) int {
	for i < len(s) && isWordPart(s[i]) {
		i++
	}

	return i
}

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	default:
		return false
	}
}

func isWordStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isWordPart(c byte) bool {
	return isWordStart(c) || isDigit(c)
}

func isTagPart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || isDigit(c)
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
