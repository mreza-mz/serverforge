package provision

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/mreza-mz/serverforge/internal/config"
	"github.com/mreza-mz/serverforge/internal/planner"
)

//go:embed ansible
var assets embed.FS

const sshChecks = "-o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=10"
const freshSSH = "-o ControlMaster=no -o ControlPath=none -o ControlPersist=no " + sshChecks

type ansibleRunner struct {
	dir string
	bin string
}

type report struct {
	TargetID string `json:"target_id"`
	Failure  string `json:"failure"`
	Changed  int    `json:"changed"`
	Skipped  int    `json:"skipped"`
	Hosts    int    `json:"hosts"`
}

func newRunner(profile config.Profile, plan planner.Plan, verifiers map[string]string) (*ansibleRunner, error) {
	bin, err := exec.LookPath("ansible-playbook")
	if err != nil {
		return nil, errors.New("ansible-playbook is required on the controller")
	}
	dir, err := os.MkdirTemp("", "serverforge-ansible-*")
	if err != nil {
		return nil, errors.New("could not prepare a private Ansible directory")
	}
	runner := &ansibleRunner{dir, bin}
	if err := runner.prepare(profile, plan, verifiers); err != nil {
		runner.close()
		return nil, err
	}
	return runner, nil
}

func (r *ansibleRunner) close() { os.RemoveAll(r.dir) }

func (r *ansibleRunner) prepare(profile config.Profile, plan planner.Plan, verifiers map[string]string) error {
	if err := fs.WalkDir(assets, "ansible", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dest := filepath.Join(r.dir, strings.TrimPrefix(path, "ansible"))
		if entry.IsDir() {
			return os.MkdirAll(dest, 0700)
		}
		data, err := assets.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dest, data, 0600)
	}); err != nil {
		return errors.New("could not unpack the embedded Ansible roles")
	}
	target := profile.Target
	host := map[string]any{
		"ansible_connection":         "local",
		"ansible_python_interpreter": "/usr/bin/python3",
	}
	if target.Connection == config.SSH {
		host["ansible_connection"] = "ssh"
		host["ansible_host"] = target.Host
		host["ansible_user"] = target.User
		host["ansible_port"] = target.Port
		host["ansible_ssh_args"] = "-o ControlMaster=auto -o ControlPersist=20s " + sshChecks
	}
	inventory := map[string]any{"all": map[string]any{"hosts": map[string]any{"serverforge": host}}}
	if err := r.writeJSON("inventory.json", inventory); err != nil {
		return err
	}

	dbs := make(map[config.Module]map[string]any)
	for engine, db := range profile.Databases {
		dbs[engine] = map[string]any{"name": db.Name, "user": db.User, "port": db.Port}
	}
	ports := make(map[string][]string)
	for engine, db := range profile.Databases {
		switch engine {
		case config.PostgreSQL:
			ports[strconv.Itoa(db.Port)] = []string{"postgres"}
		case config.MySQL, config.MariaDB:
			ports[strconv.Itoa(db.Port)] = []string{"mysqld", "mariadbd"}
		}
	}
	become := os.Geteuid() != 0
	if target.Connection == config.SSH {
		become = target.User != "root"
	}
	input := map[string]any{
		"sf_become":         become,
		"sf_remote":         profile.Target.Connection == config.SSH,
		"sf_local_ssh":      profile.Target.Connection == config.Local && os.Getenv("SSH_CONNECTION") != "",
		"sf_guard_firewall": profile.Security.UFW || profile.Security.Fail2ban,
		"sf_databases":      dbs,
		"sf_verifiers":      verifiers,
		"sf_ports":          ports,
		"sf_web_ports":      []int{},
		"sf_tls_enabled":    profile.TLS != nil,
	}
	if profile.Redis != nil {
		input["sf_redis_port"] = profile.Redis.Port
		ports[strconv.Itoa(profile.Redis.Port)] = []string{"redis-server"}
	}
	if profile.Web != nil {
		web := "nginx"
		if slices.Contains(profile.Modules, config.Caddy) {
			web = "caddy"
		}
		input["sf_web_server"] = web
		input["sf_domain"] = profile.Web.Domain
		input["sf_http_port"] = profile.Web.HTTPPort
		webPorts := []int{profile.Web.HTTPPort}
		if profile.TLS != nil {
			input["sf_tls_email"] = profile.TLS.Email
			input["sf_https_port"] = profile.TLS.Port
			webPorts = append(webPorts, profile.TLS.Port)
		}
		for _, port := range webPorts {
			ports[strconv.Itoa(port)] = []string{web}
		}
		input["sf_web_ports"] = webPorts
	}
	actions := make([]string, 0, len(plan.Actions))
	for _, action := range plan.Actions {
		actions = append(actions, action.ID)
	}
	input["sf_actions"] = actions
	return r.writeJSON("vars.json", input)
}

func (r *ansibleRunner) writeJSON(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil || os.WriteFile(filepath.Join(r.dir, name), data, 0600) != nil {
		return errors.New("could not prepare private Ansible input")
	}
	return nil
}

var fingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (r *ansibleRunner) probe(ctx context.Context) (string, error) {
	result, err := r.play(ctx, "preflight.yml")
	if err != nil {
		return "", fmt.Errorf("target preflight: %w", err)
	}
	if !fingerprint.MatchString(result.TargetID) {
		return "", errors.New("target preflight returned no valid machine identity")
	}
	return result.TargetID, nil
}

func (r *ansibleRunner) action(ctx context.Context, id, target string, dryRun bool) (Event, error) {
	step := map[string]string{"sf_role": id, "sf_target_id": target}
	if id == "ufw" || id == "fail2ban" {
		step["ansible_ssh_args"] = freshSSH
	}
	if err := r.writeJSON("step.json", step); err != nil {
		return Event{}, err
	}
	args := []string{"--extra-vars", "@step.json"}
	status := "ok"
	if dryRun {
		args = append(args, "--check")
		status = "check"
	}
	result, err := r.play(ctx, "action.yml", args...)
	return Event{Action: id, Status: status, Changed: result.Changed, Skipped: result.Skipped}, err
}

var safeTaskName = regexp.MustCompile(`^[A-Za-z0-9 _:-]{1,140}$`)

func (r *ansibleRunner) play(ctx context.Context, file string, flags ...string) (report, error) {
	args := []string{"-i", "inventory.json", "--extra-vars", "@vars.json"}
	args = append(args, flags...)
	args = append(args, file)
	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Dir = r.dir
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "ANSIBLE_") {
			cmd.Env = append(cmd.Env, item)
		}
	}
	cmd.Env = append(cmd.Env,
		"ANSIBLE_CONFIG="+filepath.Join(r.dir, "ansible.cfg"),
		"ANSIBLE_HOME="+filepath.Join(r.dir, "home"),
		"ANSIBLE_SSH_CONTROL_PATH_DIR="+filepath.Join(r.dir, "cp"),
		"ANSIBLE_LOCAL_TEMP="+filepath.Join(r.dir, "tmp"),
	)
	cmd.Stderr = io.Discard
	var output bytes.Buffer
	cmd.Stdout = &output
	err := cmd.Run()
	var result report
	decoded := json.Unmarshal(output.Bytes(), &result) == nil
	if err != nil {
		if ctx.Err() != nil {
			return report{}, errors.New("execution interrupted")
		}
		if decoded && safeTaskName.MatchString(result.Failure) {
			return report{}, fmt.Errorf("Ansible failed at %s", result.Failure)
		}
		return report{}, errors.New("Ansible failed before reporting a safe task result")
	}
	if !decoded || result.Hosts != 1 {
		return report{}, errors.New("Ansible returned an invalid result")
	}
	return result, nil
}
