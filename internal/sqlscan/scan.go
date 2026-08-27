package sqlscan

import "strings"

// tokKind marks the few token shapes classification needs. Strings, comments,
// dollar-quoted bodies, numbers, and other punctuation are dropped entirely.
type tokKind uint8

const (
	kindWord  tokKind = iota // an unquoted word, stored uppercased (a keyword candidate)
	kindIdent                // a quoted identifier, stored lowercased (never a keyword)
	kindOpen                 // (
	kindClose                // )
)

type token struct {
	kind tokKind
	text string
}

// tokenize splits sql into top-level statements, each a slice of tokens. It
// skips string literals, line and block comments, dollar-quoted bodies, and the
// contents of quoted identifiers so that keywords hidden in them are never
// mistaken for commands.
func tokenize(sql string) [][]token {
	var stmts [][]token
	cur := make([]token, 0, 8)
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
			i = skipString(sql, i+1)
		case c == '"':
			j := skipString(sql, i+1)
			cur = append(cur, token{kind: kindIdent, text: quotedText(sql, i, j)})
			i = j
		case c == '$':
			if end, ok := skipDollarQuote(sql, i); ok {
				i = end
			} else {
				i = skipWord(sql, i+1) // parameter such as $1
			}
		case c == '(':
			cur = append(cur, token{kind: kindOpen})
			i++
		case c == ')':
			cur = append(cur, token{kind: kindClose})
			i++
		case c == ';':
			stmts = append(stmts, cur)
			cur = make([]token, 0, 8)
			i++
		case isWordStart(c):
			j := skipWord(sql, i+1)
			cur = append(cur, token{kind: kindWord, text: strings.ToUpper(sql[i:j])})
			i = j
		default:
			i++
		}
	}
	stmts = append(stmts, cur)

	return stmts
}

// quotedText returns the lowercased content of a quoted identifier spanning
// s[start:end] (quotes included), so a quoted GUC name folds to compare.
func quotedText(s string, start, end int) string {
	inner := s[start+1 : end-1]

	return strings.ToLower(strings.ReplaceAll(inner, `""`, `"`))
}

func skipLineComment(s string, i int) int {
	for i < len(s) && s[i] != '\n' && s[i] != '\r' {
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

// skipString skips a string literal or quoted identifier whose opening quote at
// i-1 has been consumed, honoring the doubled-quote escape, and returns the
// index just past the closing quote.
func skipString(s string, i int) int {
	quote := s[i-1]
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
	if k := strings.Index(s[j+1:], tag); k >= 0 {
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

// isWordPart includes '$' so that identifiers such as x$a$ read as one word and
// their inner '$' is not taken to start a dollar-quoted string.
func isWordPart(c byte) bool {
	return isWordStart(c) || isDigit(c) || c == '$'
}

func isTagPart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || isDigit(c)
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
