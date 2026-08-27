package ledger

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// LastHash returns the Hash of the last record in the ledger file at path, so a
// new Sink can continue the chain across restarts. A missing file yields "".
func LastHash(path string) (string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("open ledger: %w", err)
	}
	defer func() { _ = f.Close() }()

	last := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec struct {
			Hash string `json:"hash"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			return "", fmt.Errorf("parse ledger tail: %w", err)
		}
		last = rec.Hash
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read ledger: %w", err)
	}

	return last, nil
}
