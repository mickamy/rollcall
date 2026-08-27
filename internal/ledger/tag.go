package ledger

import (
	"strconv"
	"strings"
)

// rowsFromTag reads the affected-row count from a CommandComplete tag such as
// "SELECT 5", "INSERT 0 3", "UPDATE 2", or "COPY 10"; it returns 0 when the tag
// carries no count.
func rowsFromTag(tag string) int {
	fields := strings.Fields(tag)
	if len(fields) == 0 {
		return 0
	}

	n, err := strconv.Atoi(fields[len(fields)-1])
	if err != nil {
		return 0
	}

	return n
}
