package ledger

import "time"

func defaultNow() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
