package ledger

// SetNow overrides the record clock for tests and returns a restore function.
func SetNow(t func() string) func() {
	prev := now
	now = t

	return func() { now = prev }
}
