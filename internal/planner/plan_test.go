package planner

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mreza-mz/serverforge/internal/config"
	"github.com/mreza-mz/serverforge/internal/vault"
)

func TestBuildOrdersDependenciesAndRequiresSecurityApprovals(t *testing.T) {
	profile, err := config.Load(filepath.Join("..", "..", "examples", "ssh.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	profile.Modules = append([]config.Module{config.DockerCompose, config.Docker}, profile.Modules...)
	profile.Security.Fail2ban = true
	plan, err := Build(profile)
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{"docker", "docker_compose", "caddy", "ssl", "fail2ban", "security_updates", "ufw"}
	wantApprovals := []string{"ssl", "fail2ban", "security_updates", "ufw"}
	var order, approvals []string
	seen := make(map[string]bool)
	for _, action := range plan.Actions {
		order = append(order, action.ID)
		for _, prerequisite := range action.After {
			if !seen[prerequisite] {
				t.Fatalf("%s must follow %s", action.ID, prerequisite)
			}
		}
		seen[action.ID] = true
		if action.SecurityApproval {
			approvals = append(approvals, action.ID)
		}
	}
	if !slices.Equal(order, wantOrder) || !slices.Equal(approvals, wantApprovals) {
		t.Fatalf("unexpected action order or approvals, got %v and %v", order, approvals)
	}
	if !slices.Equal(plan.Actions[1].After, []string{"docker"}) ||
		!slices.Equal(plan.Actions[3].After, []string{"caddy"}) {
		t.Fatal("module dependencies are missing")
	}
	firewall := plan.Actions[len(plan.Actions)-1]
	if len(plan.RequiredChecks) == 0 || len(firewall.Checks) < 3 ||
		!slices.Contains(firewall.Settings, Setting{"Profile SSH port", "22"}) ||
		!slices.Contains(firewall.Settings, Setting{"Allow HTTPS TCP", "443"}) {
		t.Fatal("firewall plan omitted SSH safeguards or port settings")
	}
	slices.Reverse(profile.Modules)
	reordered, err := Build(profile)
	if err != nil || reordered.ID != plan.ID {
		t.Fatal("reordering a module list changed the execution plan")
	}
	profile.Target.Port++
	changed, err := Build(profile)
	if err != nil || changed.ID == plan.ID {
		t.Fatal("changing the target SSH port did not change the plan ID")
	}
}

func TestPlanBindsCredentialsWithoutPublishingThem(t *testing.T) {
	profile := config.Profile{
		Version: config.Version,
		Target:  config.Target{Connection: config.Local},
		Modules: []config.Module{config.PostgreSQL, config.Redis},
		Databases: map[config.Module]config.Database{
			config.PostgreSQL: {Name: "app", User: "app_owner", Port: 5432},
		},
		Redis: &config.RedisSettings{Port: 6379},
	}
	const passphrase = "test-only-vault-passphrase"
	const fakePassword = "test-only-service-password"
	var err error
	profile.Vault, err = vault.Encrypt(map[string]string{
		"postgresql_password": fakePassword,
		"redis_password":      fakePassword,
	}, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Build(profile)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "ANSIBLE_VAULT") ||
		strings.Contains(string(data), fakePassword) || strings.Contains(string(data), passphrase) {
		t.Fatal("plan exposed secret material")
	}
	if len(plan.Actions) != 2 || !plan.Actions[0].SecurityApproval || !plan.Actions[1].SecurityApproval {
		t.Fatal("database and Redis credential changes need security approval")
	}
	if !slices.Contains(plan.Actions[0].Settings, Setting{"Database", "app"}) ||
		!slices.Contains(plan.Actions[1].Settings, Setting{"Port", "6379"}) {
		t.Fatal("plan omitted selected settings")
	}

	profile.Vault, err = vault.Encrypt(map[string]string{
		"postgresql_password": "test-only-new-password",
		"redis_password":      fakePassword,
	}, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := Build(profile)
	if err != nil || changed.ID == plan.ID {
		t.Fatal("changing the credential payload did not change the plan ID")
	}
}

func TestBuildRejectsInvalidProfilesAndSupportsNoOp(t *testing.T) {
	if _, err := Build(config.Profile{}); err == nil {
		t.Fatal("planner accepted an invalid profile")
	}
	plan, err := Build(config.Profile{Version: config.Version, Target: config.Target{Connection: config.Local}})
	if err != nil || len(plan.Actions) != 0 || plan.ID == "" {
		t.Fatal("expected a valid plan with zero actions")
	}
}
