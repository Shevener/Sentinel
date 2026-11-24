package lab

import "testing"

// TestAttackScenarios runs the full attack lab and fails on any deviation
// from the documented expected result.
func TestAttackScenarios(t *testing.T) {
	keys, err := GenKeys()
	if err != nil {
		t.Fatal(err)
	}
	res := RunAll(keys)
	if len(res) < 60 {
		t.Fatalf("unexpectedly few test cases: %d", len(res))
	}
	for _, r := range res {
		if !r.Pass {
			t.Errorf("%s %s\n  expected: %s\n  actual:   %s", r.ID, r.Scenario, r.Expected, r.Actual)
		}
	}
}
