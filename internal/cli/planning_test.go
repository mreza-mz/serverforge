package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mreza-mz/serverforge/internal/approval"
	"github.com/mreza-mz/serverforge/internal/planner"
)

func TestPlanAndApproveFromProfile(t *testing.T) {
	profile := filepath.Join("..", "..", "examples", "ssh.yaml")
	path := filepath.Join(t.TempDir(), "approval.json")
	var output, diagnostics bytes.Buffer
	run := func(args ...string) int {
		output.Reset()
		diagnostics.Reset()
		return Run(t.Context(), args, strings.NewReader(""), &output, &diagnostics)
	}
	if run("plan", "--config", profile) != 0 ||
		!strings.Contains(output.String(), "Requires separate security approval.") ||
		!strings.Contains(output.String(), "stage SSH allow rules") {
		t.Fatal("human-readable plan omitted approval or SSH safeguards")
	}
	if run("plan", "--config", profile, "--json", "--log-json") != 0 {
		t.Fatal("could not get JSON execution plan")
	}
	checkLogs(t, diagnostics.String())
	var plan planner.Plan
	if json.Unmarshal(output.Bytes(), &plan) != nil || plan.ID == "" || len(plan.Actions) != 4 {
		t.Fatal("unexpected JSON plan")
	}

	args := []string{"approve", "--config", profile, "--output", path}
	for _, extra := range [][]string{
		{},
		{"--plan-id", plan.ID},
		{"--non-interactive", "--plan-id", "sha256:stale"},
		{"--non-interactive", "--plan-id", plan.ID, "--approve-security", "ssl"},
	} {
		if run(append(slices.Clone(args), extra...)...) != 1 {
			t.Fatal("inadequate approval succeeded")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("failed approval wrote a file")
		}
	}
	args = append(args, "--non-interactive", "--plan-id", plan.ID,
		"--approve-security", "ssl", "--approve-security", "security_updates", "--approve-security", "ufw", "--log-json")
	if run(args...) != 0 {
		t.Fatal("explicit non-interactive approval failed")
	}
	checkLogs(t, diagnostics.String())
	var receipt approval.Receipt
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &receipt) != nil || receipt.PlanID != plan.ID ||
		!slices.Equal(receipt.SecurityActions, []string{"ssl", "security_updates", "ufw"}) {
		t.Fatal("approved actions were not recorded")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("receipt must be owner-only")
	}
	if run(args...) != 1 {
		t.Fatal("second approval replaced existing file")
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, current) {
		t.Fatal("receipt changed after a failed write")
	}
}
