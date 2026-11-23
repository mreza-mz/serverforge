package approval

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/mreza-mz/serverforge/internal/config"
	"github.com/mreza-mz/serverforge/internal/planner"
)

func TestApprovalRequiresExactReview(t *testing.T) {
	profile, err := config.Load(filepath.Join("..", "..", "examples", "ssh.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Build(profile)
	if err != nil {
		t.Fatal(err)
	}
	required := []string{"ssl", "security_updates", "ufw"}
	for _, tc := range []struct {
		name string
		id   string
		ids  []string
	}{
		{"missing plan ID", "", required},
		{"stale plan ID", "sha256:stale", required},
		{"missing action", plan.ID, required[:2]},
		{"duplicate action", plan.ID, []string{"ssl", "ssl", "security_updates", "ufw"}},
		{"unknown action", plan.ID, []string{"ssl", "security_updates", "unlisted"}},
		{"unexpected ordinary action", plan.ID, []string{"ssl", "security_updates", "ufw", "caddy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(plan, tc.id, tc.ids); err == nil {
				t.Fatal("expected incomplete or stale consent to fail")
			}
		})
	}

	receipt, err := New(plan, plan.ID, []string{"ufw", "ssl", "security_updates"})
	if err != nil || receipt.PlanID != plan.ID || receipt.Version != 1 ||
		receipt.ApprovedAt.IsZero() || !slices.Equal(receipt.SecurityActions, required) {
		t.Fatal("did not record consent for the reviewed actions")
	}
}

func TestApprovalWithNoSecurityChangesAndEmptyPlan(t *testing.T) {
	profile := config.Profile{
		Version: config.Version, Target: config.Target{Connection: config.Local}, Modules: []config.Module{config.Docker},
	}
	plan, err := planner.Build(profile)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := New(plan, plan.ID, nil)
	if err != nil || receipt.SecurityActions == nil || len(receipt.SecurityActions) != 0 {
		t.Fatal("expected approval with an empty security action list")
	}
	profile.Modules = nil
	plan, err = planner.Build(profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(plan, plan.ID, nil); err == nil {
		t.Fatal("expected no-op plan to reject approval")
	}
}
