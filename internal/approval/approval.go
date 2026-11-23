// Package approval records explicit consent for a specific execution plan.
package approval

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/mreza-mz/serverforge/internal/planner"
	"github.com/mreza-mz/serverforge/internal/privatefile"
)

type Receipt struct {
	Version         int       `json:"version"`
	PlanID          string    `json:"plan_id"`
	SecurityActions []string  `json:"security_actions"`
	ApprovedAt      time.Time `json:"approved_at"`
}

func New(plan planner.Plan, reviewedID string, securityIDs []string) (Receipt, error) {
	if len(plan.Actions) == 0 {
		return Receipt{}, errors.New("there are no planned actions to approve")
	}
	if reviewedID == "" || plan.ID != reviewedID {
		return Receipt{}, errors.New("the supplied plan ID does not match the current plan")
	}
	approved := make(map[string]bool, len(securityIDs))
	for _, id := range securityIDs {
		approved[id] = true
	}
	required := make([]string, 0)
	for _, action := range plan.Actions {
		if !action.SecurityApproval {
			continue
		}
		if !approved[action.ID] {
			return Receipt{}, errors.New("approve each listed security action exactly once")
		}
		required = append(required, action.ID)
	}
	if len(required) != len(securityIDs) || len(required) != len(approved) {
		return Receipt{}, errors.New("approve each listed security action exactly once")
	}
	return Receipt{1, plan.ID, required, time.Now().UTC()}, nil
}

func (r Receipt) SaveNew(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return errors.New("could not encode approval receipt")
	}
	if err := privatefile.WriteNew(path, append(data, '\n')); err != nil {
		if errors.Is(err, privatefile.ErrExists) {
			return errors.New("approval receipt already exists")
		}
		return err
	}
	return nil
}
