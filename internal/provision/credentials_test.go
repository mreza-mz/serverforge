package provision

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mreza-mz/serverforge/internal/config"
	"github.com/mreza-mz/serverforge/internal/planner"
	"github.com/mreza-mz/serverforge/internal/vault"
)

func TestControllerWritesOnlyVerifiers(t *testing.T) {
	const passphrase = "unit-test-vault-passphrase"
	const password = "unit-test-password !"
	profile := config.Profile{
		Version: config.Version,
		Target:  config.Target{Connection: config.SSH, Host: "app.example.test", User: "ubuntu", Port: 22},
		Modules: []config.Module{config.PostgreSQL, config.MySQL, config.Redis},
		Databases: map[config.Module]config.Database{
			config.PostgreSQL: {Name: "db_pg", User: "app_pg", Port: 5432},
			config.MySQL:      {Name: "db_mysql", User: "app_mysql", Port: 3306},
		},
		Redis: &config.RedisSettings{Port: 6379},
	}
	var err error
	profile.Vault, err = vault.Encrypt(map[string]string{
		"postgresql_password": password, "mysql_password": password, "redis_password": password,
	}, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := credentials(profile, "test-invalid-password"); err == nil {
		t.Fatal("incorrect Vault passphrase was accepted")
	}
	plan, err := planner.Build(profile)
	if err != nil {
		t.Fatal(err)
	}
	verifiers, err := credentials(profile, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	runner := ansibleRunner{dir: t.TempDir()}
	if err := runner.prepare(profile, plan, verifiers); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(runner.dir, "vars.json")
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), password) || strings.Contains(string(data), passphrase) ||
		strings.Contains(string(data), "ANSIBLE_VAULT") {
		t.Fatal("Ansible input exposed a plaintext or Vault value")
	}
	var vars struct {
		Verifiers map[string]string `json:"sf_verifiers"`
	}
	info, err := os.Stat(name)
	if err != nil || info.Mode().Perm() != 0600 || json.Unmarshal(data, &vars) != nil ||
		!strings.HasPrefix(vars.Verifiers["postgresql"], "SCRAM-SHA-256$4096:") ||
		!strings.HasPrefix(vars.Verifiers["mysql"], "$A$005$") ||
		len(vars.Verifiers["mysql"]) != 70 || len(vars.Verifiers["redis"]) != 64 {
		t.Fatal("expected private configuration containing service verifiers")
	}
}

func TestMySQLDigestMatchesOpenSSLCrypt(t *testing.T) {
	bin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl unavailable")
	}
	const salt = "1234567890123456"
	const password = "test-only-value"
	cmd := exec.CommandContext(t.Context(), bin, "passwd", "-5", "-salt", salt, "-stdin")
	cmd.Stdin = strings.NewReader(password + "\n")
	output, err := cmd.Output()
	if err != nil {
		t.Fatal("could not compute the reference SHA-256 crypt digest")
	}
	if actual := mysqlVerifier(password, salt); actual != "$A$005$"+salt+strings.TrimPrefix(strings.TrimSpace(string(output)), "$5$"+salt+"$") {
		t.Fatal("caching SHA-2 digest diverges from the reference crypt digest")
	}
}
