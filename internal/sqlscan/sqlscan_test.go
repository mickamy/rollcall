package sqlscan_test

import (
	"strings"
	"testing"

	"github.com/mickamy/rollcall/internal/sqlscan"
)

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		sql  string
		want []sqlscan.Kind
	}{
		"select":                 {"select 1", []sqlscan.Kind{sqlscan.Select}},
		"select cte":             {"with t as (select 1) select * from t", []sqlscan.Kind{sqlscan.Select}},
		"values":                 {"values (1),(2)", []sqlscan.Kind{sqlscan.Select}},
		"insert":                 {"insert into t values (1)", []sqlscan.Kind{sqlscan.Insert}},
		"update":                 {"update t set x = 1", []sqlscan.Kind{sqlscan.Update}},
		"delete":                 {"delete from t", []sqlscan.Kind{sqlscan.Delete}},
		"truncate":               {"truncate t", []sqlscan.Kind{sqlscan.Truncate}},
		"create":                 {"create table t (id int)", []sqlscan.Kind{sqlscan.DDL}},
		"set":                    {"set search_path to public", []sqlscan.Kind{sqlscan.Set}},
		"begin":                  {"begin", []sqlscan.Kind{sqlscan.Tx}},
		"show":                   {"show all", []sqlscan.Kind{sqlscan.Cursor}},
		"call":                   {"call do_work()", []sqlscan.Kind{sqlscan.Call}},
		"empty":                  {"", []sqlscan.Kind{sqlscan.Empty}},
		"comment only":           {"-- just a comment\n", []sqlscan.Kind{sqlscan.Empty}},
		"leading comment":        {"/* c */ select 1", []sqlscan.Kind{sqlscan.Select}},
		"leading paren select":   {"(select 1) union (select 2)", []sqlscan.Kind{sqlscan.Select}},
		"data modifying cte":     {"with d as (delete from t returning *) select * from d", []sqlscan.Kind{sqlscan.Delete}},
		"explain select":         {"explain select 1", []sqlscan.Kind{sqlscan.Explain}},
		"explain update":         {"explain update t set x = 1", []sqlscan.Kind{sqlscan.Explain}},
		"explain analyze update": {"explain analyze update t set x = 1", []sqlscan.Kind{sqlscan.Update}},
		"explain analyze select": {"explain (analyze, buffers) select 1", []sqlscan.Kind{sqlscan.Select}},
		"explain analyze ctas":   {"explain analyze create table t as select 1", []sqlscan.Kind{sqlscan.DDL}},
		"select into":            {"select id into newt from t", []sqlscan.Kind{sqlscan.SelectInto}},
		"copy from stdin":        {"copy t from stdin", []sqlscan.Kind{sqlscan.CopyFrom}},
		"copy from with":         {"copy t from stdin with (format csv)", []sqlscan.Kind{sqlscan.CopyFrom}},
		"copy to stdout":         {"copy t to stdout", []sqlscan.Kind{sqlscan.CopyTo}},
		"copy to file":           {"copy t to '/tmp/x.csv'", []sqlscan.Kind{sqlscan.CopyExternal}},
		"copy to program":        {"copy t to program 'cat'", []sqlscan.Kind{sqlscan.CopyExternal}},
		"copy query to stdout":   {"copy (select * from t) to stdout", []sqlscan.Kind{sqlscan.CopyTo}},
		"multi statement":        {"select 1; update t set x = 1", []sqlscan.Kind{sqlscan.Select, sqlscan.Update}},
		"trailing semicolon":     {"select 1;", []sqlscan.Kind{sqlscan.Select, sqlscan.Empty}},
		"unknown":                {"frobnicate t", []sqlscan.Kind{sqlscan.Unknown}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := sqlscan.Classify(tt.sql)
			if len(got) != len(tt.want) {
				t.Fatalf("Classify(%q) = %v, want %v", tt.sql, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Classify(%q)[%d] = %v, want %v", tt.sql, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestMutatingIgnoresKeywordsInsideLiteralsAndIdentifiers(t *testing.T) {
	t.Parallel()

	readOnly := []string{
		`select * from orders where status = 'delete pending'`,
		`select "update" from t`,
		`select 'insert' || 'update' as note`,
		`select $$ delete from t $$ as body`,
		`select $tag$ update t $tag$`,
		`select col from t -- update t set x = 1`,
		`select col /* insert into t */ from t`,
		`select delete_flag, update_ts from t`,
		`select 1 as x$a$`,
	}
	for _, sql := range readOnly {
		if sqlscan.Mutating(sql) {
			t.Errorf("Mutating(%q) = true, want false", sql)
		}
	}

	mutating := []string{
		`update t set x = 1`,
		`with d as (delete from t returning *) select * from d`,
		`explain analyze delete from t`,
		`copy t from stdin`,
		`copy t to program 'cat'`,
		`select id into newt from t`,
		`select 1; drop table t`,
	}
	for _, sql := range mutating {
		if !sqlscan.Mutating(sql) {
			t.Errorf("Mutating(%q) = false, want true", sql)
		}
	}
}

// These are the injection tricks a client could use to hide a write from a
// lexical scanner; each must be seen for what it really is.
func TestClassifyResistsHidingStatements(t *testing.T) {
	t.Parallel()

	// A carriage-return ends a line comment in PostgreSQL, so the INSERT is real.
	if !sqlscan.Mutating("select 1 --c\rinsert into t values (1)") {
		t.Error("CR line-comment: hidden INSERT not detected")
	}
	// x$a$ is one identifier, not the start of a dollar-quoted body, so the
	// INSERT between the fake tags is a real statement.
	sql := "select 1 as x$a$; insert into t values (1); select $a$ $a$"
	if !sqlscan.Mutating(sql) {
		t.Errorf("dollar-in-identifier: hidden INSERT not detected in %q", sql)
	}
}

func TestDisablesReadOnly(t *testing.T) {
	t.Parallel()

	disabling := []string{
		`set default_transaction_read_only = off`,
		`SET default_transaction_read_only TO false`,
		`set "default_transaction_read_only" = off`,
		`set transaction read write`,
		`begin read write`,
		`start transaction read write`,
		`set session characteristics as transaction read write`,
		`reset default_transaction_read_only`,
		`reset all`,
		`select set_config('default_transaction_read_only', 'off', false)`,
	}
	for _, sql := range disabling {
		if !disables(sql) {
			t.Errorf("DisablesReadOnly(%q) = false, want true", sql)
		}
	}

	safe := []string{
		`set search_path to public`,
		`set time zone 'UTC'`,
		`begin`,
		`begin transaction isolation level serializable`,
		`select 1`,
		`set role readonly`,
	}
	for _, sql := range safe {
		if disables(sql) {
			t.Errorf("DisablesReadOnly(%q) = true, want false", sql)
		}
	}
}

func disables(sql string) bool {
	for _, f := range sqlscan.Scan(sql) {
		if f.DisablesReadOnly {
			return true
		}
	}

	return false
}

func TestFingerprint(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"select * from t where id = 42":            "SELECT * FROM T WHERE ID = ?",
		"select id from t where email = 'a@b.com'": "SELECT ID FROM T WHERE EMAIL = ?",
		"insert into t values (1, 'x'), (2, 'y')":  "INSERT INTO T VALUES (?, ?), (?, ?)",
		"select   col   from t -- note\n":          "SELECT COL FROM T",
		`select "MixedCase" from t where x = $1`:   `SELECT "mixedcase" FROM T WHERE X = ?`,
		"select $$body$$ as b":                     "SELECT ? AS B",
		"select 3.14, 1e9 from t":                  "SELECT ?, ? FROM T",
	}
	for sql, want := range tests {
		if got := sqlscan.Fingerprint(sql); got != want {
			t.Errorf("Fingerprint(%q) = %q, want %q", sql, got, want)
		}
	}
}

func TestEscapeStringsDoNotLeak(t *testing.T) {
	t.Parallel()

	// In an E'' string a backslash escapes the quote, so the words inside must
	// not surface as identifiers in the fingerprint or flip classification.
	sql := `select id from t where name = E'O\'Brien said delete from t'`
	fp := sqlscan.Fingerprint(sql)
	if strings.Contains(fp, "BRIEN") || strings.Contains(fp, "DELETE") {
		t.Errorf("Fingerprint leaked E-string content: %q", fp)
	}
	if sqlscan.Mutating(sql) {
		t.Errorf("Mutating(%q) = true; the DELETE is inside an E-string", sql)
	}
}
