package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/mreza-mz/serverforge/internal/vault"
)

const minimal = "version: 1\ntarget:\n  connection: local\n"

func TestExampleProfiles(t *testing.T) {
	for _, name := range []string{"local.yaml", "ssh.yaml"} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(filepath.Join("..", "..", "examples", name)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStrictProfileParsing(t *testing.T) {
	const sensitive = "TEST-should-never-appear-in-diagnostics"
	cases := map[string]string{
		"unknown root key":    minimal + sensitive + ": 1\n",
		"plaintext password":  minimal + "modules: [postgresql]\ndatabases:\n  postgresql:\n    name: app\n    user: app\n    port: 5432\n    password: " + sensitive + "\n",
		"unredacted YAML":     minimal + "vault: [" + sensitive + "\n",
		"malicious file type": "version: [" + sensitive + "]\ntarget: {connection: local}\n",
		"plaintext vault":     minimal + "modules: [redis]\nredis: {port: 6379}\nvault: " + sensitive + "\n",
		"wrong version":       strings.Replace(minimal, "version: 1", "version: 2", 1),
		"duplicate root key":  minimal + "version: 1\n",
		"duplicate security":  minimal + "security: {ufw: false, ufw: true}\n",
		"extra document":      minimal + "---\n",
		"anchor":              minimal + "security: {ufw: &approved true}\n",
		"custom mapping tag":  "!custom\n" + minimal,
		"merge":               minimal + "security: {<<: {ufw: true}}\n",
		"unknown approval":    minimal + "security: {ssh_passwords: true}\n",
		"implicit approval":   minimal + "security: {ufw: yes}\n",
		"quoted approval":     minimal + "security: {ufw: 'true'}\n",
		"null approval":       minimal + "security: {ufw: null}\n",
		"missing target":      "version: 1\n",
		"file over limit":     minimal + "#" + strings.Repeat("x", maxProfileSize),
		"trailing bad data":   minimal + "---\n[" + sensitive,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(input))
			if err == nil {
				t.Fatal("wanted an error")
			}
			if strings.Contains(err.Error(), sensitive) {
				t.Fatal("input leaked in diagnostic")
			}
		})
	}
}

func TestModuleAndPortValidation(t *testing.T) {
	cases := map[string]string{
		"unknown module":    "modules: [ufw]",
		"duplicate module":  "modules: [docker, docker]",
		"compose alone":     "modules: [docker_compose]",
		"both proxies":      "modules: [nginx, caddy]",
		"both mysql forks":  "modules: [mysql, mariadb]",
		"tls alone":         "modules: [ssl]",
		"no tls details":    "modules: [nginx, ssl]\nweb: {domain: app.example.test, http_port: 80}",
		"missing web":       "modules: [nginx]",
		"extra web":         "web: {domain: app.example.test, http_port: 80}",
		"missing db":        "modules: [postgresql]",
		"extra db":          "databases: {postgresql: {name: app, user: app, port: 5432}}",
		"invalid db name":   "modules: [postgresql]\ndatabases: {postgresql: {name: 'bad name', user: app, port: 5432}}",
		"missing redis":     "modules: [redis]",
		"missing vault":     "modules: [redis]\nredis: {port: 6379}",
		"port collision":    "modules: [nginx, ssl]\nweb: {domain: app.example.test, http_port: 443}\ntls: {email: admin@example.test, port: 443}",
		"port out of range": "modules: [nginx]\nweb: {domain: app.example.test, http_port: 65536}",
		"ip as domain":      "modules: [nginx]\nweb: {domain: 192.0.2.1, http_port: 80}",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(minimal + input)); err == nil {
				t.Fatal("wanted validation to fail")
			}
		})
	}
}

func TestSSHTargetValidation(t *testing.T) {
	for _, value := range []string{"alpha", "app.example.test", "192.0.2.24", "2001:db8::24"} {
		if err := ValidateHost(value); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range []string{
		"target: {connection: local, port: 22}",
		"target: {connection: ssh, host: app.example.test, user: ubuntu}",
		"target: {connection: ssh, host: --option, user: ubuntu, port: 22}",
		"target: {connection: ssh, host: app.example.test, user: '-o', port: 22}",
		"target: {connection: ssh, host: app.example.test, user: ubuntu, port: 80}\nmodules: [nginx]\nweb: {domain: app.example.test, http_port: 80}",
	} {
		if _, err := Parse(strings.NewReader("version: 1\n" + input)); err == nil {
			t.Fatal("wanted invalid target or port to fail")
		}
	}
}

func TestProfileSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "target.yaml")
	const fakePassword = "test-only-password"
	const fakePassphrase = "test-only-vault-passphrase"
	ciphertext, err := vault.Encrypt(map[string]string{"postgresql_password": fakePassword, "redis_password": fakePassword}, fakePassphrase)
	if err != nil {
		t.Fatal(err)
	}
	p := Profile{
		Version:   Version,
		Target:    Target{Connection: SSH, Host: "app.example.test", User: "ubuntu", Port: 2222},
		Modules:   []Module{PostgreSQL, Redis},
		Databases: map[Module]Database{PostgreSQL: {Name: "app", User: "app_owner", Port: 5432}},
		Redis:     &RedisSettings{Port: 6379},
		Security:  Security{Fail2ban: true},
		Vault:     ciphertext,
	}
	if err := SaveNew(path, p); err != nil {
		t.Fatal(err)
	}
	fromDisk, err := Load(path)
	if err != nil || !reflect.DeepEqual(p, fromDisk) {
		t.Fatal("profile did not round-trip")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), fakePassword) || strings.Contains(string(data), fakePassphrase) {
		t.Fatal("profile contains plaintext credentials")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("profile permissions must be 0600")
	}

	p.Security.UFW = true
	if err := SaveNew(path, p); err == nil {
		t.Fatal("overwrote an existing profile")
	}
	after, err := Load(path)
	if err != nil || !reflect.DeepEqual(fromDisk, after) {
		t.Fatal("existing profile changed")
	}
}

func TestConcurrentSaveNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.yaml")
	p := Profile{Version: Version, Target: Target{Connection: Local}}
	results := make(chan error, 2)
	var pending sync.WaitGroup
	for range 2 {
		pending.Go(func() { results <- SaveNew(path, p) })
	}
	pending.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("only one concurrent save should succeed")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "target.yaml" {
		t.Fatal("profile save left unexpected files")
	}
}
