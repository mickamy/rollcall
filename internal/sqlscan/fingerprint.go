package sqlscan

import "strings"

// Fingerprint returns sql with its literal values removed, so statements of the
// same shape share a fingerprint and no literal (which may be personal data) is
// kept. String, escape-string, dollar-quoted, and numeric literals become '?';
// comments are dropped; whitespace is collapsed to single spaces. Identifiers
// and keywords are preserved (uppercased for words, lowercased for quoted
// identifiers).
func Fingerprint(sql string) string {
	var b strings.Builder
	space := false
	write := func(tok string) {
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteString(tok)
	}

	for i, n := 0, len(sql); i < n; {
		c := sql[i]
		switch {
		case isSpace(c):
			space = true
			i++
		case isComment(sql, i):
			i = skipComment(sql, i)
			space = true
		default:
			var tok string
			i, tok = fingerprintToken(sql, i)
			write(tok)
		}
	}

	return b.String()
}

func isComment(s string, i int) bool {
	if i+1 >= len(s) {
		return false
	}

	return (s[i] == '-' && s[i+1] == '-') || (s[i] == '/' && s[i+1] == '*')
}

func skipComment(s string, i int) int {
	if s[i] == '-' {
		return skipLineComment(s, i+2)
	}

	return skipBlockComment(s, i+2)
}

// fingerprintToken consumes one non-space, non-comment token and returns the
// next index and the text to emit for it.
func fingerprintToken(sql string, i int) (int, string) {
	n := len(sql)
	c := sql[i]
	switch {
	case (c == 'e' || c == 'E') && i+1 < n && sql[i+1] == '\'':
		return skipEString(sql, i+2), "?"
	case c == '\'':
		return skipString(sql, i+1), "?"
	case c == '"':
		j := skipString(sql, i+1)

		return j, `"` + quotedText(sql, i, j) + `"`
	case c == '$':
		if end, ok := skipDollarQuote(sql, i); ok {
			return end, "?"
		}

		return skipWord(sql, i+1), "?"
	case isDigit(c):
		return skipNumber(sql, i), "?"
	case isWordStart(c):
		j := skipWord(sql, i+1)

		return j, strings.ToUpper(sql[i:j])
	default:
		return i + 1, string(c)
	}
}

func skipNumber(s string, i int) int {
	for i < len(s) && (isDigit(s[i]) || s[i] == '.' || s[i] == 'e' || s[i] == 'E') {
		i++
	}

	return i
}
