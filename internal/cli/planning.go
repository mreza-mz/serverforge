package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/mreza-mz/serverforge/internal/approval"
	"github.com/mreza-mz/serverforge/internal/config"
	"github.com/mreza-mz/serverforge/internal/planner"
	"github.com/mreza-mz/serverforge/internal/wizard"
	"github.com/spf13/cobra"
)

func showPlan(out io.Writer, profile config.Profile, asJSON bool, log logEvent) error {
	plan, err := planner.Build(profile)
	if err != nil {
		return commandError{err}
	}
	log("plan_built", "plan", "action_count", len(plan.Actions))
	if asJSON {
		return writeJSON(out, plan)
	}
	return writePlan(out, plan)
}

func approveCommand(log logEvent) *cobra.Command {
	var configPath, outputPath, planID string
	var nonInteractive bool
	var securityIDs []string
	cmd := &cobra.Command{
		Use:   "approve",
		Short: "Review and record approval for an execution plan",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if configPath == "" || outputPath == "" {
				return commandError{errors.New("approve requires --config and --output")}
			}
			if !nonInteractive && (cmd.Flags().Changed("plan-id") || cmd.Flags().Changed("approve-security")) {
				return commandError{errors.New("--plan-id and --approve-security require --non-interactive")}
			}
			log("command_started", "approve")
			profile, err := config.Load(configPath)
			if err != nil {
				return commandError{err}
			}
			plan, err := planner.Build(profile)
			if err != nil {
				return commandError{err}
			}
			reviewedID, reviewedSecurity := planID, securityIDs
			if !nonInteractive {
				reviewedSecurity, err = collectPlanApproval(cmd, plan, log)
				if err != nil {
					return err
				}
				reviewedID = plan.ID
			}
			receipt, err := approval.New(plan, reviewedID, reviewedSecurity)
			if err != nil {
				return commandError{err}
			}
			if cmd.Context().Err() != nil {
				return commandError{errors.New("approval interrupted")}
			}
			if err := receipt.SaveNew(outputPath); err != nil {
				return commandError{err}
			}
			log("approval_recorded", "approve", "security_action_count", len(receipt.SecurityActions))
			return writeText(cmd.OutOrStdout(), "Approval receipt saved.")
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to the YAML profile")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "destination JSON approval receipt")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "approve using an explicitly reviewed plan ID and security action IDs")
	cmd.Flags().StringVar(&planID, "plan-id", "", "plan ID from the reviewed plan")
	cmd.Flags().StringArrayVar(&securityIDs, "approve-security", nil, "security action ID from the reviewed plan (repeat for each action)")
	return cmd
}

func collectPlanApproval(cmd *cobra.Command, plan planner.Plan, log logEvent) ([]string, error) {
	if !isTerminal(cmd.InOrStdin()) || !isTerminal(cmd.OutOrStdout()) || !isTerminal(cmd.ErrOrStderr()) {
		return nil, commandError{errors.New("interactive approval requires a terminal. Use --non-interactive with an explicitly reviewed plan for automation")}
	}
	if err := writePlan(cmd.OutOrStdout(), plan); err != nil {
		return nil, err
	}
	approved, err := wizard.ConfirmPlan(cmd.Context(), cmd.InOrStdin(), cmd.ErrOrStderr(), plan)
	if err != nil {
		log("approval_canceled", "approve")
		return nil, commandError{err}
	}
	return approved, nil
}

func writePlan(out io.Writer, plan planner.Plan) error {
	var report strings.Builder
	fmt.Fprintf(&report, "Execution plan %s\n", plan.ID)
	if plan.Target.Connection == config.SSH {
		fmt.Fprintf(&report, "Target %s on %s (SSH port %d)\n", plan.Target.User, plan.Target.Host, plan.Target.Port)
	} else {
		fmt.Fprintln(&report, "Target local Ubuntu machine")
	}
	if len(plan.Actions) == 0 {
		fmt.Fprintln(&report, "\nNo actions selected.")
	}
	if len(plan.RequiredChecks) > 0 {
		fmt.Fprintln(&report, "\nRequired target checks")
		for _, check := range plan.RequiredChecks {
			fmt.Fprintln(&report, "-", check)
		}
	}
	for i, action := range plan.Actions {
		fmt.Fprintf(&report, "\n%d. %s\n   %s\n", i+1, action.ID, action.Summary)
		if action.SecurityApproval {
			fmt.Fprintln(&report, "   Requires separate security approval.")
		}
		if len(action.After) > 0 {
			fmt.Fprintln(&report, "   After", strings.Join(action.After, ", "))
		}
		for _, setting := range action.Settings {
			fmt.Fprintf(&report, "   %s = %s\n", setting.Name, setting.Value)
		}
		for _, check := range action.Checks {
			fmt.Fprintln(&report, "   -", check)
		}
	}
	if _, err := io.WriteString(out, report.String()); err != nil {
		return commandError{errors.New("could not write plan")}
	}
	return nil
}
