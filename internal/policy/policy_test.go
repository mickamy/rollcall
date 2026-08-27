package policy_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/mickamy/rollcall/internal/policy"
	"github.com/mickamy/rollcall/internal/wire"
)

func TestParseReadsRolesAndFailMode(t *testing.T) {
	t.Parallel()

	p := load(t, `
fail: closed
roles:
  agent_ops:
    agent: claude-ops
    purpose: incident-investigation
    read_only: true
  app_rw:
    agent: web
`)

	if !p.FailClosed {
		t.Error("FailClosed: got false, want true")
	}
	if got := p.Roles["agent_ops"]; got.Agent != "claude-ops" || !got.ReadOnly {
		t.Errorf("agent_ops: got %+v", got)
	}
	if got := p.Roles["app_rw"]; got.ReadOnly {
		t.Errorf("app_rw: got read-only, want writable")
	}
}

func TestParseRejectsUnknownFieldsAndFailValues(t *testing.T) {
	t.Parallel()

	if _, err := policy.Parse([]byte("fail: sideways")); err == nil {
		t.Error("bad fail value: got nil error")
	}
	if _, err := policy.Parse([]byte("roles:\n  r:\n    reed_only: true")); err == nil {
		t.Error("unknown field: got nil error")
	}
}

func TestReadOnlyRolePrimesAndDeniesWrites(t *testing.T) {
	t.Parallel()

	p := load(t, "roles:\n  agent_ops:\n    read_only: true\n")
	enf := p.Resolve(wire.Startup{User: "agent_ops"})

	if !slices.Contains(enf.Prime, "SET default_transaction_read_only = on") {
		t.Errorf("Prime: got %v, want it to set the read-only transaction default", enf.Prime)
	}

	if v := deny(enf, "select id from t"); v.Deny {
		t.Errorf("select: got denied (%q), want allowed", v.Message)
	}

	v := deny(enf, "update t set x = 1")
	if !v.Deny || !strings.Contains(v.Message, "UPDATE") {
		t.Errorf("update: got %+v, want a read-only denial naming UPDATE", v)
	}
}

func TestReadOnlyRoleDeniesEscapeHatches(t *testing.T) {
	t.Parallel()

	p := load(t, "roles:\n  agent_ops:\n    read_only: true\n")
	enf := p.Resolve(wire.Startup{User: "agent_ops"})

	hatches := []string{
		"set default_transaction_read_only = off",
		`set "default_transaction_read_only" = off`,
		"begin read write",
		"select set_config('default_transaction_read_only','off',false)",
	}
	for _, sql := range hatches {
		v := deny(enf, sql)
		if !v.Deny || !strings.Contains(v.Message, "read-write") {
			t.Errorf("escape hatch %q: got %+v, want a read-write denial", sql, v)
		}
	}
}

func TestWritableRoleAllowsEverythingAndDoesNotPrime(t *testing.T) {
	t.Parallel()

	p := load(t, "roles:\n  app_rw:\n    agent: web\n")
	enf := p.Resolve(wire.Startup{User: "app_rw"})

	if len(enf.Prime) != 0 {
		t.Errorf("Prime: got %v, want none for a writable role", enf.Prime)
	}
	if v := deny(enf, "delete from t"); v.Deny {
		t.Errorf("delete for a writable role: got denied (%q), want allowed", v.Message)
	}
}

func TestUnlistedRoleHonorsFailMode(t *testing.T) {
	t.Parallel()

	open := load(t, "roles: {}\n")
	if v := deny(open.Resolve(wire.Startup{User: "ghost"}), "delete from t"); v.Deny {
		t.Errorf("fail-open unknown role: got denied (%q), want allowed", v.Message)
	}

	closed := load(t, "fail: closed\nroles: {}\n")
	v := deny(closed.Resolve(wire.Startup{User: "ghost"}), "select 1")
	if !v.Deny || !strings.Contains(v.Message, "ghost") {
		t.Errorf("fail-closed unknown role: got %+v, want a denial naming the role", v)
	}
}

func TestZeroPolicyAllowsEverything(t *testing.T) {
	t.Parallel()

	var p policy.Policy
	if v := deny(p.Resolve(wire.Startup{User: "anyone"}), "drop table t"); v.Deny {
		t.Errorf("zero policy: got denied (%q), want allowed", v.Message)
	}
}

func deny(enf wire.Enforcement, sql string) wire.Verdict {
	return enf.Handler.Statement(wire.Statement{SQL: sql})
}

func load(t *testing.T, src string) policy.Policy {
	t.Helper()

	p, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	return p
}
