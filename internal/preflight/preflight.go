// Package preflight checks prerequisites by reading local system information.
package preflight

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/mreza-mz/serverforge/internal/config"
)

type Status string

const (
	Pass     Status = "pass"
	Warning  Status = "warning"
	Fail     Status = "fail"
	Deferred Status = "deferred"
)

type Check struct {
	ID      string `json:"id"`
	Status  Status `json:"status"`
	Message string `json:"message"`
}

type Report struct {
	Scope  string  `json:"scope"`
	Ready  bool    `json:"ready"`
	Checks []Check `json:"checks"`
}

type probes struct {
	readFile func(string) ([]byte, error)
	lookPath func(string) (string, error)
	euid     func() int
	platform string
}

func Run(target config.Target) Report {
	return inspect(target, probes{
		readFile: os.ReadFile,
		lookPath: exec.LookPath,
		euid:     os.Geteuid,
		platform: runtime.GOOS,
	})
}

func inspect(target config.Target, system probes) Report {
	report := Report{Scope: "local_target", Ready: true}
	if target.Connection == config.SSH {
		report.Scope = "ssh_controller"
		report.Checks = append(report.Checks,
			system.tool("ssh_client", "ssh", Fail),
			Check{"remote_target", Deferred, "Remote OS, access and services require a future remote preflight."},
		)
	} else {
		report.Checks = append(report.Checks,
			system.ubuntu(),
			system.tool("python3", "python3", Warning),
			system.privilege(),
		)
	}
	report.Checks = append(report.Checks,
		system.tool("ansible_playbook", "ansible-playbook", Warning),
		system.tool("ansible_vault", "ansible-vault", Warning),
	)
	for _, check := range report.Checks {
		if check.Status == Fail {
			report.Ready = false
		}
	}
	return report
}

func (p probes) ubuntu() Check {
	const id = "ubuntu_release"
	if p.platform != "linux" {
		return Check{id, Fail, "Local targets require Ubuntu Linux."}
	}
	data, err := p.readFile("/etc/os-release")
	if errors.Is(err, fs.ErrNotExist) {
		data, err = p.readFile("/usr/lib/os-release")
	}
	if err != nil {
		return Check{id, Fail, "Could not read local OS release information."}
	}

	values := make(map[string]string)
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && (key == "ID" || key == "VERSION_ID") {
			values[key] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	if values["ID"] != "ubuntu" {
		return Check{id, Fail, "Local targets require Ubuntu Linux."}
	}
	switch values["VERSION_ID"] {
	case "22.04", "24.04", "26.04":
		return Check{id, Pass, "Supported Ubuntu LTS release detected."}
	default:
		return Check{id, Fail, "Supported local releases are Ubuntu 22.04, 24.04 and 26.04 LTS."}
	}
}

func (p probes) tool(id, name string, missing Status) Check {
	if _, err := p.lookPath(name); err != nil {
		return Check{id, missing, name + " is missing from PATH."}
	}
	return Check{id, Pass, name + " is available on PATH."}
}

func (p probes) privilege() Check {
	const id = "privilege"
	if p.euid() == 0 {
		return Check{id, Pass, "Local process is running as root."}
	}
	if _, err := p.lookPath("sudo"); err == nil {
		return Check{id, Warning, "sudo is available. Escalation permissions require verification."}
	}
	return Check{id, Warning, "Local process is unprivileged and sudo is missing from PATH."}
}
