package policy_test

import (
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

func TestResolveReadOnlyDeniesWrites(t *testing.T) {
	t.Parallel()

	p := load(t, `
roles:
  agent_ops:
    read_only: true
`)
	h := p.Resolve(wire.Startup{User: "agent_ops"})

	if v := h.Statement(wire.Statement{SQL: "select * from t"}); v.Deny {
		t.Errorf("select: got denied (%q), want allowed", v.Message)
	}

	v := h.Statement(wire.Statement{SQL: "update t set x = 1"})
	if !v.Deny {
		t.Fatal("update: got allowed, want denied")
	}
	if !strings.Contains(v.Message, "UPDATE") || !strings.Contains(v.Message, "read-only") {
		t.Errorf("update denial message: got %q", v.Message)
	}
}

func TestResolveWritableRoleAllowsEverything(t *testing.T) {
	t.Parallel()

	p := load(t, "roles:\n  app_rw:\n    agent: web\n")
	h := p.Resolve(wire.Startup{User: "app_rw"})

	if v := h.Statement(wire.Statement{SQL: "delete from t"}); v.Deny {
		t.Errorf("delete for a writable role: got denied (%q), want allowed", v.Message)
	}
}

func TestResolveUnknownRoleHonorsFailMode(t *testing.T) {
	t.Parallel()

	open := load(t, "roles: {}\n")
	if v := open.Resolve(wire.Startup{User: "ghost"}).Statement(wire.Statement{SQL: "delete from t"}); v.Deny {
		t.Errorf("fail-open unknown role: got denied (%q), want allowed", v.Message)
	}

	closed := load(t, "fail: closed\nroles: {}\n")
	v := closed.Resolve(wire.Startup{User: "ghost"}).Statement(wire.Statement{SQL: "select 1"})
	if !v.Deny || !strings.Contains(v.Message, "ghost") {
		t.Errorf("fail-closed unknown role: got %+v, want a denial naming the role", v)
	}
}

func TestZeroPolicyAllowsEverything(t *testing.T) {
	t.Parallel()

	var p policy.Policy
	if v := p.Resolve(wire.Startup{User: "anyone"}).Statement(wire.Statement{SQL: "drop table t"}); v.Deny {
		t.Errorf("zero policy: got denied (%q), want allowed", v.Message)
	}
}

func load(t *testing.T, src string) policy.Policy {
	t.Helper()

	p, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	return p
}
