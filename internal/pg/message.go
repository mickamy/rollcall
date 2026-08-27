package pg

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	protocolVersion3  = 196608
	sslRequestCode    = 80877103
	gssEncRequestCode = 80877104
	cancelRequestCode = 80877102

	// maxStartupPacket matches PostgreSQL's own MaxStartupPacketLength.
	maxStartupPacket = 10000
	maxAuthMessage   = 1 << 20

	// headerLen is the message type byte plus the length word.
	headerLen = 5
	// lengthLen is the length word, counted inside the length itself.
	lengthLen = 4

	maxBodyLen = 1<<31 - 1 - lengthLen
)

const (
	typeQuery           = 'Q'
	typeParse           = 'P'
	typeBind            = 'B'
	typeDescribe        = 'D'
	typeExecute         = 'E'
	typeClose           = 'C'
	typeFlush           = 'H'
	typeSync            = 'S'
	typeFunctionCall    = 'F'
	typeTerminate       = 'X'
	typePassword        = 'p'
	typeAuthentication  = 'R'
	typeErrorResponse   = 'E'
	typeReadyForQuery   = 'Z'
	typeCopyInResponse  = 'G'
	typeRowDescription  = 'T'
	typeDataRow         = 'D'
	typeCommandComplete = 'C'
)

const (
	authOK        = 0
	authSASLFinal = 12
)

const (
	fieldSeverity     = 'S'
	fieldSeverityText = 'V'
	fieldCode         = 'C'
	fieldMessage      = 'M'
	fieldHint         = 'H'

	sqlStateInsufficientPrivilege = "42501"
	sqlStateProgramLimitExceeded  = "54000"
	sqlStateFeatureNotSupported   = "0A000"
)

var errMalformed = errors.New("malformed message")

// readStartupPacket returns the whole untyped startup packet, length word included.
func readStartupPacket(r *bufio.Reader) ([]byte, error) {
	var length [lengthLen]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, fmt.Errorf("read startup length: %w", err)
	}

	n := binary.BigEndian.Uint32(length[:])
	if n < 2*lengthLen || n > maxStartupPacket {
		return nil, fmt.Errorf("%w: startup packet length %d", errMalformed, n)
	}

	packet := make([]byte, n)
	copy(packet, length[:])
	if _, err := io.ReadFull(r, packet[lengthLen:]); err != nil {
		return nil, fmt.Errorf("read startup packet: %w", err)
	}

	return packet, nil
}

// readHeader returns a typed message's type and body length, leaving the body unread.
func readHeader(r *bufio.Reader) (typ byte, bodyLen uint32, err error) {
	var header [headerLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, 0, fmt.Errorf("read header: %w", err)
	}

	n := binary.BigEndian.Uint32(header[1:])
	if n < lengthLen {
		return 0, 0, fmt.Errorf("%w: %q with length %d", errMalformed, header[0], n)
	}

	return header[0], n - lengthLen, nil
}

func readMessage(r *bufio.Reader, maxBody uint32) (typ byte, body []byte, err error) {
	typ, n, err := readHeader(r)
	if err != nil {
		return 0, nil, err
	}
	if n > maxBody {
		return 0, nil, fmt.Errorf("%w: %q body of %d bytes exceeds %d", errMalformed, typ, n, maxBody)
	}

	body = make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, fmt.Errorf("read %q body: %w", typ, err)
	}

	return typ, body, nil
}

// readBody reads a message body whose length the client chose, committing
// memory only as bytes actually arrive.
func readBody(r *bufio.Reader, n uint32) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(int(min(n, 64<<10)))
	if _, err := io.CopyN(&buf, r, int64(n)); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return buf.Bytes(), nil
}

func discard(r *bufio.Reader, n uint32) error {
	if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
		return fmt.Errorf("discard body: %w", err)
	}

	return nil
}

func writeMessage(w *bufio.Writer, typ byte, body []byte) error {
	if len(body) > maxBodyLen {
		return fmt.Errorf("%w: %q body of %d bytes", errMalformed, typ, len(body))
	}

	if err := writeHeader(w, typ, uint32(len(body))); err != nil { //nolint:gosec // bounded by the maxBodyLen check above
		return err
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("write %q: %w", typ, err)
	}

	return nil
}

// stageHeader writes a message header into a growable buffer, for batching
// several messages before they are forwarded together.
func stageHeader(buf *bytes.Buffer, typ byte, bodyLen int) {
	buf.WriteByte(typ)
	var length [lengthLen]byte
	binary.BigEndian.PutUint32(length[:], uint32(bodyLen+lengthLen)) //nolint:gosec // bodyLen is bounded by the caller
	buf.Write(length[:])
}

func writeHeader(w *bufio.Writer, typ byte, bodyLen uint32) error {
	var header [headerLen]byte
	header[0] = typ
	binary.BigEndian.PutUint32(header[1:], bodyLen+lengthLen)

	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("write %q header: %w", typ, err)
	}

	return nil
}

// forward streams one message whose header has already been read from r to w
// without flushing.
func forward(w *bufio.Writer, typ byte, bodyLen uint32, r io.Reader) error {
	if err := writeHeader(w, typ, bodyLen); err != nil {
		return err
	}
	if _, err := io.CopyN(w, r, int64(bodyLen)); err != nil {
		return fmt.Errorf("forward %q body: %w", typ, err)
	}

	return nil
}

func flush(w *bufio.Writer) error {
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}

	return nil
}

// columnNames reads the field names from a RowDescription body.
func columnNames(body []byte) []string {
	if len(body) < 2 {
		return nil
	}
	count := int(binary.BigEndian.Uint16(body))
	body = body[2:]

	names := make([]string, 0, count)
	for range count {
		name, rest, err := cstring(body)
		if err != nil {
			break
		}
		names = append(names, name)
		if len(rest) < 18 { // tableOID(4) col(2) typeOID(4) len(2) mod(4) format(2)
			break
		}
		body = rest[18:]
	}

	return names
}

// rowValues reads the values of the given column indices from a DataRow body.
// A null column yields a nil slice.
func rowValues(body []byte, capture []int) [][]byte {
	if len(body) < 2 {
		return nil
	}
	count := int(binary.BigEndian.Uint16(body))
	body = body[2:]

	fields := make([][]byte, 0, count)
	for range count {
		if len(body) < 4 {
			break
		}
		n := int32(binary.BigEndian.Uint32(body)) //nolint:gosec // length is a signed int32 by protocol
		body = body[4:]
		if n < 0 {
			fields = append(fields, nil)

			continue
		}
		if len(body) < int(n) {
			break
		}
		fields = append(fields, body[:n])
		body = body[n:]
	}

	out := make([][]byte, 0, len(capture))
	for _, c := range capture {
		if c >= 0 && c < len(fields) {
			out = append(out, fields[c])
		}
	}

	return out
}

// commandTag reads the tag from a CommandComplete body, dropping its terminator.
func commandTag(body []byte) string {
	return string(bytes.TrimSuffix(body, []byte{0}))
}

func cstring(b []byte) (s string, rest []byte, err error) {
	value, rest, ok := bytes.Cut(b, []byte{0})
	if !ok {
		return "", nil, fmt.Errorf("%w: unterminated string", errMalformed)
	}

	return string(value), rest, nil
}

// errorMessage extracts the human-readable message field from an ErrorResponse body.
func errorMessage(body []byte) string {
	for len(body) > 0 && body[0] != 0 {
		field := body[0]
		value, rest, err := cstring(body[1:])
		if err != nil {
			return ""
		}
		if field == fieldMessage {
			return value
		}
		body = rest
	}

	return ""
}

func errorResponse(code, message, hint string) []byte {
	var b bytes.Buffer
	writeField(&b, fieldSeverity, "ERROR")
	writeField(&b, fieldSeverityText, "ERROR")
	writeField(&b, fieldCode, code)
	writeField(&b, fieldMessage, message)
	if hint != "" {
		writeField(&b, fieldHint, hint)
	}
	b.WriteByte(0)

	return b.Bytes()
}

func writeField(b *bytes.Buffer, field byte, value string) {
	b.WriteByte(field)
	b.WriteString(value)
	b.WriteByte(0)
}
