// Package policy resolves a per-session guard from a YAML file: it maps a
// connection's database role to an agent, a purpose, and the statements that
// role may run.
package policy

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/mickamy/rollcall/internal/sqlscan"
	"github.com/mickamy/rollcall/internal/wire"
)

// readOnlyPrime is run on the upstream for a read-only role. It makes the server
// refuse every write, including writes performed through functions such as
// nextval, which the statement classifier cannot see.
const readOnlyPrime = "SET default_transaction_read_only = on"

// Policy decides what each database role may do. The zero value denies nothing;
// load a file to enforce rules.
type Policy struct {
	// FailClosed denies connections whose role is not listed. The default,
	// fail-open, lets unlisted roles through unchanged.
	FailClosed bool
	Roles      map[string]Role
}

// Role is the set of rules bound to one database role.
type Role struct {
	Agent    string
	Purpose  string
	ReadOnly bool
}

var _ wire.Guard = (*Policy)(nil)

type file struct {
	Fail  string          `yaml:"fail"`
	Roles map[string]role `yaml:"roles"`
}

type role struct {
	Agent    string `yaml:"agent"`
	Purpose  string `yaml:"purpose"`
	ReadOnly bool   `yaml:"read_only"`
}

// Load reads and validates a policy file.
func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}

	return parse(data)
}

func parse(data []byte) (Policy, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return Policy{}, fmt.Errorf("parse policy: %w", err)
	}

	failClosed, err := parseFail(f.Fail)
	if err != nil {
		return Policy{}, err
	}

	p := Policy{FailClosed: failClosed, Roles: make(map[string]Role, len(f.Roles))}
	for name, r := range f.Roles {
		p.Roles[name] = Role(r)
	}

	return p, nil
}

func parseFail(s string) (bool, error) {
	switch s {
	case "", "open":
		return false, nil
	case "closed":
		return true, nil
	default:
		return false, fmt.Errorf("policy: fail must be \"open\" or \"closed\", got %q", s)
	}
}

// Resolve returns the enforcement for a session, binding the rules of the role
// that matches the connection's database user.
func (p Policy) Resolve(startup wire.Startup) wire.Enforcement {
	role, ok := p.Roles[startup.User]
	if !ok {
		return p.unlisted(startup.User)
	}

	if !role.ReadOnly {
		return wire.Enforcement{Handler: allow()}
	}

	return wire.Enforcement{
		Prime:   []string{readOnlyPrime},
		Handler: wire.HandlerFunc(readOnly),
	}
}

func (p Policy) unlisted(user string) wire.Enforcement {
	if !p.FailClosed {
		return wire.Enforcement{Handler: allow()}
	}

	return wire.Enforcement{Handler: wire.HandlerFunc(func(wire.Statement) wire.Verdict {
		return wire.Verdict{
			Deny:    true,
			Message: fmt.Sprintf("no policy for role %q", user),
			Hint:    "add the role to the policy, or connect as a configured role",
		}
	})}
}

// readOnly denies statements that write or that could turn read-only mode off.
// The server-side read-only transaction is the real guarantee; this gives a
// clear, early refusal and stops the client from disabling it.
func readOnly(stmt wire.Statement) wire.Verdict {
	for _, f := range sqlscan.Scan(stmt.SQL) {
		if f.DisablesReadOnly {
			return wire.Verdict{
				Deny:    true,
				Message: "changing this connection to read-write is not allowed",
				Hint:    "this connection is read-only; use a role that permits writes",
			}
		}
		if f.Kind.Mutating() {
			return wire.Verdict{
				Deny:    true,
				Message: fmt.Sprintf("%s is not allowed: this connection is read-only", f.Kind),
				Hint:    "use a role that permits writes, or request approval",
			}
		}
	}

	return wire.Verdict{}
}

func allow() wire.Handler {
	return wire.HandlerFunc(func(wire.Statement) wire.Verdict { return wire.Verdict{} })
}
