package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/mreza-mz/serverforge/internal/approval"
	"github.com/mreza-mz/serverforge/internal/config"
	"github.com/mreza-mz/serverforge/internal/planner"
	"github.com/mreza-mz/serverforge/internal/provision"
	"github.com/mreza-mz/serverforge/internal/wizard"
	"github.com/spf13/cobra"
)

func applyCommand(log logEvent) *cobra.Command {
	var path, receipt string
	var stdinPassphrase bool
	var options provision.Options
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply an approved execution plan to an Ubuntu target",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return executeApply(cmd, path, receipt, stdinPassphrase, options, log, "apply")
		},
	}
	cmd.Flags().StringVarP(&path, "config", "c", "", "path to the YAML profile")
	cmd.Flags().StringVar(&receipt, "approval", "", "owner-only approval receipt for the current plan")
	cmd.Flags().BoolVar(&options.DryRun, "dry-run", false, "use Ansible check mode")
	cmd.Flags().BoolVar(&options.Resume, "resume", false, "resume from an existing execution checkpoint")
	cmd.Flags().StringVar(&options.StatePath, "state", "", "checkpoint path (default beside the profile, per plan)")
	cmd.Flags().BoolVar(&stdinPassphrase, "vault-passphrase-stdin", false, "read the Vault passphrase from a single line on stdin")
	return cmd
}

func executeApply(cmd *cobra.Command, path, receipt string, stdinPassphrase bool, options provision.Options, log logEvent, operation string) error {
	if path == "" {
		return commandError{errors.New("apply requires --config")}
	}
	if options.DryRun && (options.Resume || options.StatePath != "") {
		return commandError{errors.New("--dry-run does not use an execution checkpoint")}
	}
	log("command_started", operation, "dry_run", options.DryRun, "resume", options.Resume)
	profile, err := config.Load(path)
	if err != nil {
		return commandError{err}
	}
	plan, err := planner.Build(profile)
	if err != nil {
		return commandError{err}
	}
	if err := writePlan(cmd.OutOrStdout(), plan); err != nil || len(plan.Actions) == 0 {
		return err
	}
	if receipt != "" {
		if err := approval.VerifyFile(receipt, plan); err != nil {
			return commandError{err}
		}
	} else if !options.DryRun {
		if stdinPassphrase {
			return commandError{errors.New("--vault-passphrase-stdin requires --approval for execution")}
		}
		if !isTerminal(cmd.InOrStdin()) || !isTerminal(cmd.OutOrStdout()) || !isTerminal(cmd.ErrOrStderr()) {
			return commandError{errors.New("apply requires a terminal or an explicit approval receipt")}
		}
		if _, err := wizard.ConfirmPlan(cmd.Context(), cmd.InOrStdin(), cmd.ErrOrStderr(), plan); err != nil {
			return commandError{err}
		}
	}
	if profile.Vault != "" {
		if stdinPassphrase {
			options.Passphrase, err = readPassphrase(cmd.InOrStdin())
		} else if isTerminal(cmd.InOrStdin()) && isTerminal(cmd.ErrOrStderr()) {
			options.Passphrase, err = wizard.ReadVaultPassphrase(cmd.Context(), cmd.InOrStdin(), cmd.ErrOrStderr())
		} else {
			err = errors.New("unlock Vault in a terminal or use --vault-passphrase-stdin")
		}
		if err != nil {
			return commandError{err}
		}
		defer func() { options.Passphrase = "" }()
	}
	if options.StatePath == "" {
		options.StatePath = path + "." + strings.TrimPrefix(plan.ID, "sha256:") + ".state.json"
	}
	report := func(event provision.Event) {
		log("action_result", operation, "action", event.Action, "status", event.Status, "changed", event.Changed, "skipped", event.Skipped)
		fmt.Fprintf(cmd.OutOrStdout(), "%s %s (changed %d, skipped %d)\n", event.Action, event.Status, event.Changed, event.Skipped)
	}
	if err := provision.Run(cmd.Context(), profile, plan, options, report); err != nil {
		return commandError{err}
	}
	log("execution_finished", operation, "dry_run", options.DryRun)
	return nil
}

func readPassphrase(input io.Reader) (string, error) {
	reader := bufio.NewReaderSize(input, 4098)
	password, err := reader.ReadSlice('\n')
	if err != nil && err != io.EOF {
		return "", errors.New("could not read a single Vault passphrase of at most 4096 bytes")
	}
	defer clear(password)
	value := strings.TrimSuffix(strings.TrimSuffix(string(password), "\n"), "\r")
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("provide a single Vault passphrase of at most 4096 bytes")
	}
	return value, nil
}
