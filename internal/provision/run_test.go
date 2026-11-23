package provision

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mreza-mz/serverforge/internal/planner"
)

type testRunner struct {
	id      string
	fail    string
	actions []string
	dryRun  []bool
}

func (r *testRunner) probe(context.Context) (string, error) { return r.id, nil }

func (r *testRunner) action(_ context.Context, id, _ string, dryRun bool) (Event, error) {
	r.actions = append(r.actions, id)
	r.dryRun = append(r.dryRun, dryRun)
	if id == r.fail {
		return Event{}, errors.New("test action failure")
	}
	return Event{Action: id, Status: "ok"}, nil
}

func TestResumeSkipsCompletedActionsAndChecksIdentity(t *testing.T) {
	plan := planner.Plan{ID: "plan", Actions: []planner.Action{{ID: "docker"}, {ID: "docker_compose"}}}
	options := Options{StatePath: filepath.Join(t.TempDir(), "checkpoint.json")}
	emit := func(Event) {}
	first := &testRunner{id: "example-target", fail: "docker_compose"}
	if err := execute(t.Context(), first, plan, options, emit); err == nil {
		t.Fatal("expected interrupted execution")
	}
	second := &testRunner{id: first.id}
	if err := execute(t.Context(), second, plan, options, emit); err == nil || len(second.actions) != 0 {
		t.Fatal("incomplete state requires explicit resume")
	}
	options.Resume = true
	wrongHost := &testRunner{id: "other-target"}
	if err := execute(t.Context(), wrongHost, plan, options, emit); err == nil || len(wrongHost.actions) != 0 {
		t.Fatal("resume accepted different target")
	}
	if err := execute(t.Context(), second, plan, options, emit); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(second.actions, []string{"docker_compose"}) {
		t.Fatal("resume did not start at the failed action")
	}
	second.actions = nil
	options.Resume = false
	if err := execute(t.Context(), second, plan, options, emit); err != nil ||
		!slices.Equal(second.actions, []string{"docker", "docker_compose"}) {
		t.Fatal("completed plans can be applied again")
	}
}

func TestDryRunUsesCheckModeAndDoesNotCheckpoint(t *testing.T) {
	plan := planner.Plan{ID: "plan", Actions: []planner.Action{{ID: "ufw"}}}
	backend := &testRunner{id: "example-target"}
	dir := t.TempDir()
	options := Options{StatePath: filepath.Join(dir, "plan.json"), DryRun: true}
	if err := execute(t.Context(), backend, plan, options, func(Event) {}); err != nil ||
		!slices.Equal(backend.dryRun, []bool{true}) {
		t.Fatal("dry run did not pass through check mode")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("dry run created checkpoint files")
	}
}
