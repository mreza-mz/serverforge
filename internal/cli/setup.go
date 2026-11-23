package cli

import (
	"errors"
	"os"

	"github.com/mreza-mz/serverforge/internal/provision"
	"github.com/spf13/cobra"
)

func setupCommand(log logEvent) *cobra.Command {
	var path string
	var options provision.Options
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Choose services, review the plan, and configure Ubuntu",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !isTerminal(cmd.InOrStdin()) || !isTerminal(cmd.OutOrStdout()) || !isTerminal(cmd.ErrOrStderr()) {
				return commandError{errors.New("setup requires an interactive terminal")}
			}
			if options.Resume && options.DryRun {
				return commandError{errors.New("--resume and --dry-run cannot be combined")}
			}
			if !options.Resume {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					return commandError{errors.New("choose a new profile path with --config, or use apply for an existing profile")}
				}
				if err := createProfile(cmd, path); err != nil {
					return err
				}
				log("profile_created", "setup")
			}
			return executeApply(cmd, path, "", false, options, log, "setup")
		},
	}
	cmd.Flags().StringVarP(&path, "config", "c", "profile.yaml", "YAML profile to create or resume")
	cmd.Flags().BoolVar(&options.DryRun, "dry-run", false, "create the profile and use Ansible check mode")
	cmd.Flags().BoolVar(&options.Resume, "resume", false, "resume a previously interrupted setup")
	return cmd
}
