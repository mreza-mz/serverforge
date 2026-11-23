// Package provision executes a locally approved plan with Ansible.
package provision

import (
	"context"
	"errors"
	"fmt"

	"github.com/mreza-mz/serverforge/internal/config"
	"github.com/mreza-mz/serverforge/internal/planner"
	"github.com/mreza-mz/serverforge/internal/provision/state"
)

type Options struct {
	DryRun     bool
	Resume     bool
	StatePath  string
	Passphrase string
}

type Event struct {
	Action  string `json:"action"`
	Status  string `json:"status"`
	Changed int    `json:"changed"`
	Skipped int    `json:"skipped"`
}

type backend interface {
	probe(context.Context) (string, error)
	action(context.Context, string, string, bool) (Event, error)
}

func Run(ctx context.Context, profile config.Profile, plan planner.Plan, options Options, emit func(Event)) error {
	if len(plan.Actions) == 0 {
		return nil
	}
	verifiers, err := credentials(profile, options.Passphrase)
	if err != nil {
		return err
	}
	defer clear(verifiers)
	runner, err := newRunner(profile, plan, verifiers)
	if err != nil {
		return err
	}
	defer runner.close()
	return execute(ctx, runner, plan, options, emit)
}

func execute(ctx context.Context, runner backend, plan planner.Plan, options Options, emit func(Event)) error {
	var store *state.Store
	if !options.DryRun {
		var err error
		store, err = state.Open(options.StatePath)
		if err != nil {
			return err
		}
		defer store.Close()
	}
	targetID, err := runner.probe(ctx)
	if err != nil {
		return err
	}
	emit(Event{Action: "target_preflight", Status: "ok"})
	var checkpoint state.Checkpoint
	if store != nil {
		ids := make([]string, 0, len(plan.Actions))
		for _, action := range plan.Actions {
			ids = append(ids, action.ID)
		}
		checkpoint, err = store.Start(plan.ID, targetID, ids, options.Resume)
		if err != nil {
			return err
		}
	}
	for index, action := range plan.Actions {
		if err := ctx.Err(); err != nil {
			return errors.New("provisioning interrupted")
		}
		if index < len(checkpoint.Completed) {
			emit(Event{Action: action.ID, Status: "resumed"})
			continue
		}
		event, err := runner.action(ctx, action.ID, targetID, options.DryRun)
		if err != nil {
			emit(Event{Action: action.ID, Status: "failed"})
			return fmt.Errorf("action %s: %w", action.ID, err)
		}
		if store != nil {
			checkpoint.Completed = append(checkpoint.Completed, action.ID)
			if err := store.Save(checkpoint); err != nil {
				return err
			}
		}
		emit(event)
	}
	return nil
}
