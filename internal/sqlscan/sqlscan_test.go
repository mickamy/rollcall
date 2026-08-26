package sqlscan_test

import (
	"testing"

	"github.com/mickamy/rollcall/internal/sqlscan"
)

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		sql  string
		want []sqlscan.Kind
	}{
		"select":               {"select 1", []sqlscan.Kind{sqlscan.Select}},
		"select with cte":      {"with t as (select 1) select * from t", []sqlscan.Kind{sqlscan.Select}},
		"values":               {"values (1),(2)", []sqlscan.Kind{sqlscan.Select}},
		"insert":               {"insert into t values (1)", []sqlscan.Kind{sqlscan.Insert}},
		"update":               {"update t set x = 1", []sqlscan.Kind{sqlscan.Update}},
		"delete":               {"delete from t", []sqlscan.Kind{sqlscan.Delete}},
		"truncate":             {"truncate t", []sqlscan.Kind{sqlscan.Truncate}},
		"create":               {"create table t (id int)", []sqlscan.Kind{sqlscan.DDL}},
		"drop":                 {"drop table t", []sqlscan.Kind{sqlscan.DDL}},
		"set":                  {"set search_path to public", []sqlscan.Kind{sqlscan.Set}},
		"begin":                {"begin", []sqlscan.Kind{sqlscan.Tx}},
		"show":                 {"show all", []sqlscan.Kind{sqlscan.Cursor}},
		"call":                 {"call do_work()", []sqlscan.Kind{sqlscan.Call}},
		"empty":                {"", []sqlscan.Kind{sqlscan.Empty}},
		"comment only":         {"-- just a comment\n", []sqlscan.Kind{sqlscan.Empty}},
		"leading comment":      {"/* c */ select 1", []sqlscan.Kind{sqlscan.Select}},
		"leading paren select": {"(select 1) union (select 2)", []sqlscan.Kind{sqlscan.Select}},
		"data modifying cte":   {"with d as (delete from t returning *) select * from d", []sqlscan.Kind{sqlscan.Delete}},
		"insert cte": {
			"with i as (insert into t values (1) returning id) select * from i",
			[]sqlscan.Kind{sqlscan.Insert},
		},
		"explain select":         {"explain select 1", []sqlscan.Kind{sqlscan.Explain}},
		"explain update":         {"explain update t set x = 1", []sqlscan.Kind{sqlscan.Explain}},
		"explain analyze update": {"explain analyze update t set x = 1", []sqlscan.Kind{sqlscan.Update}},
		"explain analyze select": {"explain (analyze, buffers) select 1", []sqlscan.Kind{sqlscan.Select}},
		"copy from stdin":        {"copy t from stdin", []sqlscan.Kind{sqlscan.CopyFrom}},
		"copy to stdout":         {"copy t to stdout", []sqlscan.Kind{sqlscan.CopyTo}},
		"copy query to":          {"copy (select * from t) to stdout", []sqlscan.Kind{sqlscan.CopyTo}},
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
		`select current_user`,
	}
	for _, sql := range readOnly {
		if sqlscan.Mutating(sql) {
			t.Errorf("Mutating(%q) = true, want false", sql)
		}
	}

	mutating := []string{
		`update t set x = 1`,
		`insert into t values (1)`,
		`with d as (delete from t returning *) select * from d`,
		`explain analyze delete from t`,
		`copy t from stdin`,
		`select 1; drop table t`,
		`truncate t`,
	}
	for _, sql := range mutating {
		if !sqlscan.Mutating(sql) {
			t.Errorf("Mutating(%q) = false, want true", sql)
		}
	}
}

func TestClassifyDollarQuotedFunctionBody(t *testing.T) {
	t.Parallel()

	sql := `do $$ begin delete from t; end $$`
	got := sqlscan.Classify(sql)
	if len(got) != 1 || got[0] != sqlscan.Call {
		t.Errorf("Classify(%q) = %v, want [CALL] (the DELETE is inside the body)", sql, got)
	}
}
