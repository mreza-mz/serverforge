// Package state checkpoints a single execution and serializes access to it.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"slices"

	"github.com/gofrs/flock"
	"github.com/mreza-mz/serverforge/internal/privatefile"
)

type Checkpoint struct {
	Version   int      `json:"version"`
	PlanID    string   `json:"plan_id"`
	TargetID  string   `json:"target_id"`
	Completed []string `json:"completed"`
}

type Store struct {
	path string
	lock *flock.Flock
}

func Open(path string) (*Store, error) {
	lock := flock.New(path+".lock", flock.SetPermissions(0600))
	acquired, err := lock.TryLock()
	if err != nil || !acquired {
		return nil, errors.New("could not lock the execution state")
	}
	return &Store{path, lock}, nil
}

func (s *Store) Close() { s.lock.Close() }

func (s *Store) Start(planID, targetID string, actions []string, resume bool) (Checkpoint, error) {
	current := Checkpoint{Version: 1, PlanID: planID, TargetID: targetID, Completed: []string{}}
	var prior Checkpoint
	err := privatefile.ReadJSON(s.path, &prior)
	if errors.Is(err, os.ErrNotExist) && !resume {
		return current, s.Save(current)
	}
	if err != nil {
		return Checkpoint{}, errors.New("could not read an owner-only execution checkpoint")
	}
	if prior.Version != 1 || prior.PlanID != planID || prior.TargetID != targetID ||
		prior.Completed == nil || len(prior.Completed) > len(actions) ||
		!slices.Equal(prior.Completed, actions[:len(prior.Completed)]) {
		return Checkpoint{}, errors.New("checkpoint does not match the plan, target, or action order")
	}
	if resume {
		return prior, nil
	}
	if len(prior.Completed) != len(actions) {
		return Checkpoint{}, errors.New("an incomplete execution exists. Use --resume")
	}
	return current, s.Save(current)
}

func (s *Store) Save(checkpoint Checkpoint) error {
	data, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return errors.New("could not encode execution checkpoint")
	}
	return privatefile.Replace(s.path, append(data, '\n'))
}
