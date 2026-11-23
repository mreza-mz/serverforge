package wizard

import (
	"context"
	"errors"
	"io"

	"github.com/charmbracelet/huh"
	"github.com/mreza-mz/serverforge/internal/planner"
)

func ConfirmPlan(ctx context.Context, input io.Reader, output io.Writer, plan planner.Plan) ([]string, error) {
	if len(plan.Actions) == 0 {
		return nil, errors.New("there are no planned actions to approve")
	}

	confirm := func(title, description string) error {
		var approved bool
		field := huh.NewConfirm().Title(title).Description(description).
			Affirmative("Approve").Negative("Decline").Value(&approved)
		if err := runForm(ctx, input, output, field); err != nil {
			return errors.New("approval interrupted")
		}
		if !approved {
			return errors.New("plan approval declined")
		}
		return nil
	}
	var securityIDs []string
	for _, action := range plan.Actions {
		if !action.SecurityApproval {
			continue
		}
		if err := confirm("Security approval · "+action.ID, action.Summary); err != nil {
			return nil, err
		}
		securityIDs = append(securityIDs, action.ID)
	}
	if err := confirm("Approve this execution plan?", "This saves an approval receipt on this machine."); err != nil {
		return nil, err
	}
	return securityIDs, nil
}
