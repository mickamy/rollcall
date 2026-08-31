package ledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
)

// tailWindow bounds how far back LastHash reads. Records are far smaller than
// this (fingerprints are capped), so the last complete line is always within it.
const tailWindow = 1 << 20

// LastHash returns the Hash of the last record in the ledger file at path, so a
// new Sink can continue the chain across restarts. It reads only the tail of the
// file. A missing or empty file yields "".
func LastHash(path string) (string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("open ledger: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat ledger: %w", err)
	}

	size := info.Size()
	if size == 0 {
		return "", nil
	}

	start, length := int64(0), size
	if size > tailWindow {
		start, length = size-tailWindow, tailWindow
	}
	buf := make([]byte, length)
	if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read ledger tail: %w", err)
	}

	return lastHashInTail(buf, start > 0)
}

// lastHashInTail returns the hash of the last complete record in tail. windowed
// reports whether the tail was cut from a larger file, in which case the first
// line may be incomplete and is not trusted.
func lastHashInTail(tail []byte, windowed bool) (string, error) {
	lines := bytes.Split(tail, []byte{'\n'})
	for i, raw := range slices.Backward(lines) {
		line := bytes.TrimSpace(raw)
		if len(line) == 0 {
			continue
		}

		var rec struct {
			Hash string `json:"hash"`
		}
		if err := json.Unmarshal(line, &rec); err == nil && rec.Hash != "" {
			return rec.Hash, nil
		}
		// A partial trailing write, or a line with no hash; try the record before
		// it, unless the tail window may have cut this first line short.
		if i == 0 && windowed {
			return "", fmt.Errorf("ledger: last record exceeds %d bytes; cannot resume", tailWindow)
		}
	}

	return "", nil
}
