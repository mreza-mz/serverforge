// Package planner turns a validated profile into a deterministic execution plan.
package planner

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/mreza-mz/serverforge/internal/config"
)

const version = 2

type Plan struct {
	Version        int           `json:"version"`
	ID             string        `json:"id,omitempty"`
	ProfileVersion int           `json:"profile_version"`
	Target         config.Target `json:"target"`
	RequiredChecks []string      `json:"required_checks"`
	Actions        []Action      `json:"actions"`
}

type Action struct {
	ID               string    `json:"id"`
	Summary          string    `json:"summary"`
	Settings         []Setting `json:"settings,omitempty"`
	After            []string  `json:"after,omitempty"`
	Checks           []string  `json:"checks,omitempty"`
	SecurityApproval bool      `json:"security_approval"`
}

type Setting struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func Build(profile config.Profile) (Plan, error) {
	if err := profile.Validate(); err != nil {
		return Plan{}, err
	}
	plan := Plan{
		Version:        version,
		ProfileVersion: profile.Version,
		Target:         profile.Target,
		RequiredChecks: []string{},
		Actions:        []Action{},
	}
	selected := make(map[config.Module]bool, len(profile.Modules))
	for _, module := range profile.Modules {
		selected[module] = true
	}
	if selected[config.Docker] {
		plan.Actions = append(plan.Actions, Action{
			ID: string(config.Docker), Summary: "Install Ubuntu's docker.io package and enable Docker Engine.",
		})
	}
	if selected[config.DockerCompose] {
		plan.Actions = append(plan.Actions, Action{
			ID: string(config.DockerCompose), Summary: "Install Ubuntu's docker-compose-v2 CLI plugin.",
			After: []string{string(config.Docker)},
		})
	}
	for _, engine := range config.DatabaseModules() {
		if settings, exists := profile.Databases[engine.Module]; exists {
			plan.Actions = append(plan.Actions, databaseAction(engine, settings))
		}
	}
	if profile.Redis != nil {
		plan.Actions = append(plan.Actions, Action{
			ID: string(config.Redis), Summary: "Install and enable Redis with password authentication.",
			Settings: []Setting{
				{"Port", strconv.Itoa(profile.Redis.Port)},
				{"Listener", "Loopback only"},
				{"Credential", "Ansible Vault (" + config.Redis.PasswordKey() + ")"},
			},
			SecurityApproval: true,
		})
	}
	if profile.Web != nil {
		webServer, label := config.Nginx, "Nginx"
		if selected[config.Caddy] {
			webServer, label = config.Caddy, "Caddy"
		}
		plan.Actions = append(plan.Actions, webActions(webServer, label, *profile.Web, profile.TLS)...)
	}
	if profile.Security.Fail2ban {
		plan.Actions = append(plan.Actions, Action{
			ID: "fail2ban", Summary: "Install and enable Fail2ban with an SSH jail for repeated authentication failures.",
			Checks: []string{
				"Verify the target's SSH service and log source before enabling the jail.",
				"When administering over SSH, protect the management source from lockout and verify a fresh login. Restore the prior jail state if verification fails.",
			},
			SecurityApproval: true,
		})
	}
	if profile.Security.SecurityUpdates {
		plan.Actions = append(plan.Actions, Action{
			ID: "security_updates", Summary: "Enable automatic Ubuntu security updates and leave automatic reboots disabled.",
			SecurityApproval: true,
		})
	}
	if profile.Security.UFW {
		plan.Actions = append(plan.Actions, firewallAction(profile, plan.Actions))
	}
	if len(plan.Actions) > 0 {
		plan.RequiredChecks = []string{
			"Verify target identity, supported Ubuntu release, and escalation access.",
			"Check existing services and listener ports before changing the target.",
		}
	}

	// Bind the reviewed actions to the credential payload without emitting that payload.
	hashInput := struct {
		Plan      Plan
		VaultHash [sha256.Size]byte
	}{plan, sha256.Sum256([]byte(profile.Vault))}
	encoded, err := json.Marshal(hashInput)
	if err != nil {
		return Plan{}, errors.New("could not encode plan for identification")
	}
	plan.ID = fmt.Sprintf("sha256:%x", sha256.Sum256(encoded))
	return plan, nil
}

func databaseAction(engine config.DatabaseModule, db config.Database) Action {
	return Action{
		ID:      string(engine.Module),
		Summary: fmt.Sprintf("Install and enable %s, create the database, and grant its user access.", engine.Label),
		Settings: []Setting{
			{"Database", db.Name}, {"Username", db.User}, {"Port", strconv.Itoa(db.Port)},
			{"Listener", "Loopback only"}, {"Credential", "Ansible Vault (" + engine.Module.PasswordKey() + ")"},
		},
		SecurityApproval: true,
	}
}

func webActions(server config.Module, label string, web config.Web, tls *config.TLS) []Action {
	actions := []Action{{
		ID:      string(server),
		Summary: "Install and enable " + label + " with an HTTP listener for the domain.",
		Settings: []Setting{
			{"Domain", web.Domain}, {"HTTP port", strconv.Itoa(web.HTTPPort)},
			{"Document root", "/var/www/serverforge/" + web.Domain},
		},
	}}
	if server == config.Caddy {
		actions[0].Settings = append(actions[0].Settings, Setting{"Configuration", "/etc/caddy/Caddyfile"})
	} else {
		actions[0].Settings = append(actions[0].Settings, Setting{"Configuration", "Managed Nginx site replaces the Ubuntu default site"})
	}
	if tls != nil {
		actions = append(actions, Action{
			ID:               string(config.SSL),
			Summary:          "Request and renew a TLS certificate and enable the HTTPS listener.",
			Settings:         []Setting{{"Domain", web.Domain}, {"HTTPS port", strconv.Itoa(tls.Port)}, {"Contact email", tls.Email}},
			After:            []string{string(server)},
			Checks:           []string{"Verify DNS and public ACME HTTP-01 reachability on TCP port 80."},
			SecurityApproval: true,
		})
	}
	return actions
}

func firewallAction(profile config.Profile, preceding []Action) Action {
	action := Action{
		ID:               "ufw",
		Summary:          "Install and enable UFW with inbound traffic denied by default. Allow management access and the configured web listeners.",
		SecurityApproval: true,
		Checks: []string{
			"Inspect existing rules and identify active SSH listeners and management routes.",
			"Prepare rollback to the previous rules and stage SSH allow rules before activating the firewall.",
			"When administering over SSH, verify a fresh independent login before committing the change. Restore the previous rules if verification fails.",
		},
	}
	if profile.Target.Connection == config.SSH {
		action.Settings = append(action.Settings, Setting{"Profile SSH port", strconv.Itoa(profile.Target.Port)})
	}
	if profile.Web != nil {
		action.Settings = append(action.Settings, Setting{"Allow HTTP TCP", strconv.Itoa(profile.Web.HTTPPort)})
	}
	if profile.TLS != nil {
		action.Settings = append(action.Settings, Setting{"Allow HTTPS TCP", strconv.Itoa(profile.TLS.Port)})
	}
	for _, step := range preceding {
		switch step.ID {
		case string(config.Nginx), string(config.Caddy), string(config.SSL), "fail2ban":
			action.After = append(action.After, step.ID)
		}
	}
	return action
}
