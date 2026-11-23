// Package cli implements the ServerForge command line.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"text/tabwriter"

	"github.com/mreza-mz/serverforge/internal/config"
	"github.com/mreza-mz/serverforge/internal/preflight"
	"github.com/mreza-mz/serverforge/internal/wizard"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const version = "0.1.0"

type commandError struct{ error }

func Run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) int {
	var logJSON bool
	logger := slog.New(slog.NewJSONHandler(errOut, nil))
	log := func(event, operation string, attrs ...any) {
		if logJSON {
			logger.InfoContext(ctx, event, append([]any{"operation", operation}, attrs...)...)
		}
	}

	root := &cobra.Command{
		Use:           "serverforge",
		Short:         "Create and check reusable Ubuntu provisioning profiles",
		Version:       version,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE:          func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}
	root.SetArgs(append([]string{}, args...))
	root.SetIn(in)
	root.SetOut(out)
	root.SetErr(errOut)
	root.SetHelpCommand(&cobra.Command{
		Use:   "help [command]",
		Short: "Show help for a command",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			command, remaining, err := root.Find(args)
			if err != nil || len(remaining) > 0 || command.Hidden {
				return errors.New("invalid help topic")
			}
			command.InitDefaultHelpFlag()
			command.InitDefaultVersionFlag()
			return command.Help()
		},
	})
	root.PersistentFlags().BoolVar(&logJSON, "log-json", false, "write structured diagnostics to stderr")
	root.AddCommand(
		initCommand(log),
		profileCommand("validate", "Validate a YAML profile", log, validate),
		profileCommand("preflight", "Check local prerequisites without changing the system", log, checkPreflight),
	)

	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	var operational commandError
	if errors.As(err, &operational) {
		if logJSON {
			logger.ErrorContext(ctx, "command_failed", "message", operational.Error())
		} else {
			fmt.Fprintln(errOut, "serverforge:", operational.Error())
		}
		return 1
	}

	// Cobra syntax errors can contain raw command-line arguments.
	const usage = "invalid command or arguments. See serverforge --help."
	if logJSON {
		logger.ErrorContext(ctx, "invalid_arguments", "message", usage)
	} else {
		fmt.Fprintln(errOut, "serverforge:", usage)
	}
	return 2
}

type logEvent func(event, operation string, attrs ...any)

func initCommand(log logEvent) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Interactively create a new profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if path == "" {
				return commandError{errors.New("init requires --output")}
			}
			if !isTerminal(cmd.InOrStdin()) || !isTerminal(cmd.ErrOrStderr()) {
				return commandError{errors.New("init requires a terminal. Use validate and preflight with an existing YAML profile for automation")}
			}
			log("command_started", "init")
			profile, err := wizard.Run(cmd.Context(), cmd.InOrStdin(), cmd.ErrOrStderr())
			if err != nil {
				return commandError{err}
			}
			if err := cmd.Context().Err(); err != nil {
				return commandError{errors.New("wizard interrupted")}
			}
			if err := config.SaveNew(path, profile); err != nil {
				return commandError{err}
			}
			log("profile_created", "init")
			return writeText(cmd.OutOrStdout(), "Profile saved.")
		},
	}
	cmd.Flags().StringVarP(&path, "output", "o", "", "destination YAML file")
	return cmd
}

func profileCommand(name, short string, log logEvent, run func(io.Writer, config.Profile, bool, logEvent) error) *cobra.Command {
	var path string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   name,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if path == "" {
				return commandError{errors.New("provide a YAML profile with --config")}
			}
			log("command_started", name)
			profile, err := config.Load(path)
			if err != nil {
				return commandError{err}
			}
			return run(cmd.OutOrStdout(), profile, asJSON, log)
		},
	}
	cmd.Flags().StringVarP(&path, "config", "c", "", "path to the YAML profile")
	cmd.Flags().BoolVar(&asJSON, "json", false, "write a JSON report to stdout")
	return cmd
}

func validate(out io.Writer, profile config.Profile, asJSON bool, log logEvent) error {
	log("profile_valid", "validate", "schema_version", profile.Version)
	if asJSON {
		return writeJSON(out, struct {
			Valid   bool `json:"valid"`
			Version int  `json:"schema_version"`
		}{true, profile.Version})
	}
	return writeText(out, "Profile is valid.")
}

func checkPreflight(out io.Writer, profile config.Profile, asJSON bool, log logEvent) error {
	report := preflight.Run(profile.Target)
	for _, check := range report.Checks {
		log("preflight_check", "preflight", "id", check.ID, "status", check.Status)
	}
	log("preflight_finished", "preflight", "scope", report.Scope, "ready", report.Ready)
	if asJSON {
		if err := writeJSON(out, report); err != nil {
			return err
		}
	} else if err := writePreflight(out, report); err != nil {
		return err
	}
	if !report.Ready {
		return commandError{errors.New("preflight found failing checks")}
	}
	return nil
}

func writePreflight(out io.Writer, report preflight.Report) error {
	writer := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(writer, "Preflight (%s)\n", report.Scope)
	fmt.Fprintln(writer, "CHECK\tSTATUS\tDETAIL")
	for _, check := range report.Checks {
		fmt.Fprintf(writer, "%s\t%s\t%s\n", check.ID, check.Status, check.Message)
	}
	if writer.Flush() != nil {
		return commandError{errors.New("could not write report")}
	}
	return nil
}

func writeJSON(out io.Writer, data any) error {
	if json.NewEncoder(out).Encode(data) != nil {
		return commandError{errors.New("could not write report")}
	}
	return nil
}

func writeText(out io.Writer, message string) error {
	if _, err := fmt.Fprintln(out, message); err != nil {
		return commandError{errors.New("could not write output")}
	}
	return nil
}

func isTerminal(stream any) bool {
	file, ok := stream.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}
