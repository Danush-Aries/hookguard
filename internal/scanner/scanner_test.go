package scanner

import (
	"path/filepath"
	"testing"

	"github.com/Danush-Aries/hookguard/internal/rules"
)

func TestScan_Benign(t *testing.T) {
	root := absTestdata(t, "benign")
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.SettingsAt == "" {
		t.Fatalf("expected settings.json to be discovered")
	}
	if len(res.Hooks) != 2 {
		t.Fatalf("expected 2 hooks, got %d", len(res.Hooks))
	}
	if res.Summary.Critical > 0 || res.Summary.High > 0 {
		t.Fatalf("benign fixture flagged high/critical: %+v", res.Findings)
	}
}

func TestScan_Malicious(t *testing.T) {
	root := absTestdata(t, "malicious")
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Summary.Critical == 0 {
		t.Fatalf("malicious fixture should have at least one critical finding, got %+v", res.Summary)
	}
	want := map[string]bool{"HG001": false, "HG002": false, "HG003": false, "HG004": false, "HG005": false, "HG008": false}
	for _, f := range res.Findings {
		if _, ok := want[f.RuleID]; ok {
			want[f.RuleID] = true
		}
	}
	for id, hit := range want {
		if !hit {
			t.Errorf("expected rule %s to fire on malicious fixture", id)
		}
	}
	if res.HighestSeverity() != rules.SeverityCritical {
		t.Fatalf("HighestSeverity = %s, want critical", res.HighestSeverity())
	}
}

func TestScan_Edge(t *testing.T) {
	root := absTestdata(t, "edge")
	res, err := Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	// Inline /tmp write with no cleanup -> HG007 info.
	found := false
	for _, f := range res.Findings {
		if f.RuleID == "HG007" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HG007 on edge fixture, got %+v", res.Findings)
	}
	if res.Summary.Critical > 0 || res.Summary.High > 0 {
		t.Fatalf("edge fixture should not be high/critical, got %+v", res.Summary)
	}
}

func TestScan_NoSettings(t *testing.T) {
	dir := t.TempDir()
	res, err := Scan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.SettingsAt != "" {
		t.Fatalf("expected no settings, got %s", res.SettingsAt)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(res.Findings))
	}
}

func absTestdata(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return p
}
