package sqlscan

import "strings"

// Fingerprint returns sql with its literal values removed, so statements of the
// same shape share a fingerprint and no literal (which may be personal data) is
// kept. String, dollar-quoted, and numeric literals become '?'; comments are
// dropped; whitespace is collapsed to single spaces. Identifiers and keywords
// are preserved (uppercased for words, lowercased for quoted identifiers).
func Fingerprint(sql string) string {
	var b strings.Builder
	i, n := 0, len(sql)
	space := false

	emit := func(s string) {
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteString(s)
	}

	for i < n {
		c := sql[i]
		switch {
		case isSpace(c):
			space = true
			i++
		case c == '-' && i+1 < n && sql[i+1] == '-':
			i = skipLineComment(sql, i+2)
			space = true
		case c == '/' && i+1 < n && sql[i+1] == '*':
			i = skipBlockComment(sql, i+2)
			space = true
		case c == '\'':
			i = skipString(sql, i+1)
			emit("?")
		case c == '"':
			j := skipString(sql, i+1)
			emit(`"` + quotedText(sql, i, j) + `"`)
			i = j
		case c == '$':
			if end, ok := skipDollarQuote(sql, i); ok {
				i = end
				emit("?")
			} else {
				i = skipWord(sql, i+1)
				emit("?") // parameter such as $1
			}
		case c >= '0' && c <= '9':
			for i < n && (isDigit(sql[i]) || sql[i] == '.' || sql[i] == 'e' || sql[i] == 'E') {
				i++
			}
			emit("?")
		case isWordStart(c):
			j := skipWord(sql, i+1)
			emit(strings.ToUpper(sql[i:j]))
			i = j
		case c == '(' || c == ')' || c == ',' || c == ';' || c == '*':
			emit(string(c))
			i++
		default:
			emit(string(c))
			i++
		}
	}

	return b.String()
}
