// Package wizard collects settings and builds a profile without touching the target.
package wizard

import (
	"context"
	"errors"
	"io"
	"strconv"

	"github.com/charmbracelet/huh"
	"github.com/mreza-mz/serverforge/internal/config"
	"github.com/mreza-mz/serverforge/internal/vault"
)

func Run(ctx context.Context, input io.Reader, output io.Writer) (config.Profile, error) {
	run := func(fields ...huh.Field) error {
		return runForm(ctx, input, output, fields...)
	}
	profile := config.Profile{Version: config.Version}
	if err := selectServices(run, &profile); err != nil {
		return config.Profile{}, err
	}

	ports := make(map[int]bool)
	if err := collectTarget(run, &profile.Target, ports); err != nil {
		return config.Profile{}, err
	}
	secrets := make(map[string]string)
	defer clear(secrets)
	if err := collectServices(run, &profile, ports, secrets); err != nil {
		return config.Profile{}, err
	}
	if err := securityWizard(run, &profile.Security); err != nil {
		return config.Profile{}, err
	}
	if len(secrets) > 0 {
		var err error
		profile.Vault, err = encryptCredentials(run, secrets)
		if err != nil {
			return config.Profile{}, err
		}
	}

	save := false
	if err := run(huh.NewConfirm().Title("Save this profile?").
		Description("This writes a YAML file on this machine.").
		Affirmative("Save profile").Negative("Cancel").Value(&save)); err != nil {
		return config.Profile{}, err
	}
	if !save {
		return config.Profile{}, errors.New("profile creation canceled")
	}
	return profile, profile.Validate()
}

func runForm(ctx context.Context, input io.Reader, output io.Writer, fields ...huh.Field) error {
	form := huh.NewForm(huh.NewGroup(fields...)).WithInput(input).WithOutput(output).WithShowHelp(true)
	if err := form.RunWithContext(ctx); err != nil {
		return errors.New("wizard interrupted")
	}
	return nil
}

func selectServices(run func(...huh.Field) error, profile *config.Profile) error {
	var options []huh.Option[config.Module]
	for _, option := range config.Modules() {
		options = append(options, huh.NewOption(option.Label, option.Module))
	}
	return run(huh.NewMultiSelect[config.Module]().
		Title("Which services should this profile include?").
		Description("Space toggles a service. Enter confirms the selection. Security options follow separately.").
		Options(options...).Value(&profile.Modules).
		Validate(func(modules []config.Module) error {
			_, err := config.SelectModules(modules)
			return err
		}))
}

func collectTarget(run func(...huh.Field) error, target *config.Target, ports map[int]bool) error {
	target.Connection = config.Local
	if err := run(huh.NewSelect[string]().Title("Target connection").
		Options(huh.NewOption("Local Ubuntu machine", config.Local), huh.NewOption("Ubuntu over SSH", config.SSH)).
		Value(&target.Connection)); err != nil {
		return err
	}
	if target.Connection == config.Local {
		return nil
	}
	port := "22"
	err := run(
		huh.NewInput().Title("SSH hostname or IP address").Value(&target.Host).Validate(config.ValidateHost),
		huh.NewInput().Title("SSH username").Value(&target.User).Validate(config.ValidateSSHUser),
		portInput("Existing SSH port", &port, ports),
	)
	if err == nil {
		target.Port = recordPort(port, ports)
	}
	return err
}

func collectServices(run func(...huh.Field) error, profile *config.Profile, ports map[int]bool, secrets map[string]string) error {
	selected, err := config.SelectModules(profile.Modules)
	if err != nil {
		return err
	}
	for _, option := range config.DatabaseModules() {
		if !selected[option.Module] {
			continue
		}
		database, password, err := collectDatabase(run, option, ports)
		if err != nil {
			return err
		}
		if profile.Databases == nil {
			profile.Databases = make(map[config.Module]config.Database)
		}
		profile.Databases[option.Module] = database
		secrets[option.Module.PasswordKey()] = password
	}
	if selected[config.Redis] {
		port, password := "6379", ""
		if err := run(portInput("Redis port", &port, ports),
			passwordInput("Redis password", &password, vault.ValidatePassword)); err != nil {
			return err
		}
		profile.Redis = &config.RedisSettings{Port: recordPort(port, ports)}
		secrets[config.Redis.PasswordKey()] = password
	}
	if selected[config.Nginx] || selected[config.Caddy] {
		httpPort := "80"
		profile.Web = &config.Web{}
		if err := run(
			huh.NewInput().Title("Web domain").Value(&profile.Web.Domain).Validate(config.ValidateDomain),
			portInput("HTTP port", &httpPort, ports),
		); err != nil {
			return err
		}
		profile.Web.HTTPPort = recordPort(httpPort, ports)
	}
	if selected[config.SSL] {
		httpsPort := "443"
		profile.TLS = &config.TLS{}
		if err := run(
			huh.NewInput().Title("TLS certificate contact email").Value(&profile.TLS.Email).Validate(config.ValidateEmail),
			portInput("HTTPS port", &httpsPort, ports),
		); err != nil {
			return err
		}
		profile.TLS.Port = recordPort(httpsPort, ports)
	}
	return nil
}

func collectDatabase(run func(...huh.Field) error, engine config.DatabaseModule, ports map[int]bool) (config.Database, string, error) {
	var database config.Database
	port, password := strconv.Itoa(engine.DefaultPort), ""
	err := run(
		huh.NewInput().Title(engine.Label+" database name").Value(&database.Name).Validate(engine.ValidateName),
		huh.NewInput().Title(engine.Label+" database username").Value(&database.User).Validate(engine.ValidateUser),
		portInput(engine.Label+" port", &port, ports),
		passwordInput(engine.Label+" database password", &password, vault.ValidatePassword),
	)
	if err != nil {
		return config.Database{}, "", err
	}
	database.Port = recordPort(port, ports)
	return database, password, nil
}

func securityWizard(run func(...huh.Field) error, security *config.Security) error {
	approval := func(title, description string, value *bool) huh.Field {
		return huh.NewConfirm().Title("Security Wizard · " + title).Description(description).
			Affirmative("Include in profile").Negative("Skip").Value(value)
	}
	return run(
		approval("UFW", "Record intent to configure the host firewall.", &security.UFW),
		approval("Fail2ban", "Record intent to ban clients after repeated authentication failures.", &security.Fail2ban),
		approval("Security updates", "Record intent to enable automatic security updates.", &security.SecurityUpdates),
	)
}

func encryptCredentials(run func(...huh.Field) error, secrets map[string]string) (string, error) {
	var passphrase, confirmation string
	err := run(
		passwordInput("Ansible Vault passphrase", &passphrase, vault.ValidatePassphrase).
			Description("Keep this passphrase in your password manager. The profile contains only ciphertext."),
		passwordInput("Confirm Ansible Vault passphrase", &confirmation, func(value string) error {
			if value != passphrase {
				return errors.New("passphrases must match")
			}
			return nil
		}),
	)
	if err != nil {
		return "", err
	}
	return vault.Encrypt(secrets, passphrase)
}

func passwordInput(title string, value *string, validate func(string) error) *huh.Input {
	return huh.NewInput().Title(title).Value(value).EchoMode(huh.EchoModePassword).Validate(validate)
}

func portInput(title string, value *string, ports map[int]bool) *huh.Input {
	return huh.NewInput().Title(title).Value(value).Validate(func(value string) error {
		port, err := strconv.Atoi(value)
		if err != nil {
			return errors.New("enter a port between 1 and 65535")
		}
		if err := config.ValidatePort(port); err != nil {
			return err
		}
		if ports[port] {
			return errors.New("this port is already used elsewhere in the profile")
		}
		return nil
	})
}

func recordPort(value string, ports map[int]bool) int {
	port, _ := strconv.Atoi(value) // The field has passed portInput's validation.
	ports[port] = true
	return port
}
