package preflight

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/mreza-mz/serverforge/internal/config"
)

func TestLocalReleaseChecks(t *testing.T) {
	cases := []struct {
		name, platform, osRelease string
		status                    Status
	}{
		{"jammy", "linux", "ID=ubuntu\nVERSION_ID=\"22.04\"\n", Pass},
		{"noble", "linux", "ID=ubuntu\nVERSION_ID='24.04'\n", Pass},
		{"resolute", "linux", "ID=ubuntu\nVERSION_ID=26.04\n", Pass},
		{"unsupported release", "linux", "ID=ubuntu\nVERSION_ID=20.04", Fail},
		{"ubuntu derivative", "linux", "ID=other\nID_LIKE=ubuntu\nVERSION_ID=24.04", Fail},
		{"missing release", "linux", "", Fail},
		{"non-Linux", "darwin", "ID=ubuntu\nVERSION_ID=24.04", Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			system := probes{
				platform: tc.platform,
				readFile: func(path string) ([]byte, error) {
					if path == "/etc/os-release" || tc.osRelease == "" {
						return nil, fs.ErrNotExist
					}
					if path != "/usr/lib/os-release" {
						t.Fatal("unexpected OS release path")
					}
					return []byte(tc.osRelease), nil
				},
				lookPath: func(string) (string, error) { return "", errors.New("not found") },
				euid:     func() int { return 1000 },
			}
			report := inspect(config.Target{Connection: config.Local}, system)
			if report.Scope != "local_target" || report.Ready != (tc.status == Pass) {
				t.Fatal("unexpected report status")
			}
			if byID(t, report, "ubuntu_release") != tc.status ||
				byID(t, report, "privilege") != Warning ||
				byID(t, report, "ansible_playbook") != Warning ||
				byID(t, report, "ansible_vault") != Warning {
				t.Fatal("unexpected check status")
			}
		})
	}
}

func TestSSHOnlyChecksController(t *testing.T) {
	for _, sshAvailable := range []bool{true, false} {
		t.Run(fmt.Sprintf("ssh available %t", sshAvailable), func(t *testing.T) {
			system := probes{
				lookPath: func(name string) (string, error) {
					if name == "ssh" && !sshAvailable {
						return "", errors.New("not found")
					}
					return "/fake/" + name, nil
				},
				readFile: func(string) ([]byte, error) {
					t.Fatal("SSH preflight must not inspect a target OS")
					return nil, nil
				},
			}
			report := inspect(config.Target{Connection: config.SSH, Host: "unreachable.example.test"}, system)
			if report.Scope != "ssh_controller" || report.Ready != sshAvailable ||
				byID(t, report, "remote_target") != Deferred {
				t.Fatal("expected controller-only report")
			}
		})
	}
}

func byID(t *testing.T, report Report, id string) Status {
	t.Helper()
	for _, check := range report.Checks {
		if check.ID == id {
			return check.Status
		}
	}
	t.Fatalf("missing check %s", id)
	return ""
}
