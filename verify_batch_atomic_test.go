package authzstore

import (
	"testing"
)

// countRows reports how many rows the table currently holds.
func countRows(t *testing.T, a *Adapter) int {
	t.Helper()
	var rows []*AuthzRule
	s := a.session()
	defer s.Close()
	if err := s.Find(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return len(rows)
}

// RemovePolicies documents that the batch is removed "in a single
// transaction". If a mid-batch delete fails, no earlier rule may be
// gone — a partial policy removal is an authorization change the
// caller never asked for.
func TestVerify_RemovePolicies_AtomicOnMidBatchFailure(t *testing.T) {
	eng := newTestEngine(t)
	a, err := New(eng, "authz_atomic_del_rule", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rules := [][]string{
		{"alice", "data1", "read", "allow", "", "perm-A"},
		{"boom", "data2", "write", "allow", "", "perm-B"},
		{"carol", "data3", "read", "allow", "", "perm-C"},
	}
	for _, r := range rules {
		if err := a.AddPolicy("p", "p", r); err != nil {
			t.Fatalf("seed AddPolicy: %v", err)
		}
	}
	// Fail the delete of the SECOND rule only.
	if _, err := eng.Exec(`CREATE TRIGGER abort_del BEFORE DELETE ON authz_atomic_del_rule
		WHEN OLD.v0 = 'boom' BEGIN SELECT RAISE(ABORT, 'blocked delete'); END;`); err != nil {
		t.Fatalf("trigger: %v", err)
	}

	err = a.RemovePolicies("p", "p", rules)
	if err == nil {
		t.Fatal("expected the mid-batch failure to surface")
	}
	if got := countRows(t, a); got != 3 {
		t.Fatalf("partial removal: %d rows remain, want all 3 (atomic rollback)", got)
	}
}

// AddPolicies documents the same single-transaction guarantee on insert.
func TestVerify_AddPolicies_AtomicOnMidBatchFailure(t *testing.T) {
	eng := newTestEngine(t)
	a, err := New(eng, "authz_atomic_ins_rule", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rules := [][]string{
		{"alice", "data1", "read", "allow", "", "perm-A"},
		{"boom", "data2", "write", "allow", "", "perm-B"},
		{"carol", "data3", "read", "allow", "", "perm-C"},
	}
	if _, err := eng.Exec(`CREATE TRIGGER abort_ins BEFORE INSERT ON authz_atomic_ins_rule
		WHEN NEW.v0 = 'boom' BEGIN SELECT RAISE(ABORT, 'blocked insert'); END;`); err != nil {
		t.Fatalf("trigger: %v", err)
	}

	err = a.AddPolicies("p", "p", rules)
	if err == nil {
		t.Fatal("expected the mid-batch failure to surface")
	}
	if got := countRows(t, a); got != 0 {
		t.Fatalf("partial insert: %d rows present, want 0 (atomic rollback)", got)
	}
}
