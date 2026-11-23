package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadOnlyCommands(t *testing.T) {
	path := filepath.Join("..", "..", "examples", "ssh.yaml")
	var out, diagnostics bytes.Buffer
	if code := Run(t.Context(), []string{"validate", "--config", path, "--json", "--log-json"}, strings.NewReader(""), &out, &diagnostics); code != 0 {
		t.Fatalf("validate exited %d", code)
	}
	var validation struct {
		Valid   bool `json:"valid"`
		Version int  `json:"schema_version"`
	}
	if err := json.Unmarshal(out.Bytes(), &validation); err != nil || !validation.Valid || validation.Version != 1 {
		t.Fatal("invalid validation JSON")
	}
	checkLogs(t, diagnostics.String())
	if strings.Contains(out.String()+diagnostics.String(), "app.example.test") {
		t.Fatal("profile data leaked in output")
	}

	out.Reset()
	diagnostics.Reset()
	// Use a path containing a fake executable to verify preflight never runs it.
	fakeBin := t.TempDir()
	fakeSSH := filepath.Join(fakeBin, "ssh")
	probe := filepath.Join(fakeBin, "was-invoked")
	if err := os.WriteFile(fakeSSH, []byte("#!/bin/sh\n: > \"${0%/*}/was-invoked\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin)
	if code := Run(t.Context(), []string{"preflight", "--config", path, "--json", "--log-json"}, strings.NewReader(""), &out, &diagnostics); code != 0 {
		t.Fatalf("preflight exited %d", code)
	}
	var report struct {
		Scope  string `json:"scope"`
		Ready  bool   `json:"ready"`
		Checks []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || !report.Ready || report.Scope != "ssh_controller" {
		t.Fatal("invalid SSH controller report")
	}
	if !strings.Contains(out.String(), `"status":"deferred"`) {
		t.Fatal("remote checks must be deferred")
	}
	if _, err := os.Stat(probe); !os.IsNotExist(err) {
		t.Fatal("preflight executed the SSH client")
	}
	checkLogs(t, diagnostics.String())
}

func TestSafeErrors(t *testing.T) {
	const sensitive = "test-secret-on-command-line"
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("password: "+sensitive+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args []string
		code int
	}{
		{[]string{"--log-json", "validate", "-c", path}, 1},
		{[]string{"--log-json", "validate"}, 1},
		{[]string{"--log-json", "validate", "-c", sensitive}, 1},
		{[]string{"--log-json", "validate", "--unknown=" + sensitive}, 2},
		{[]string{"--log-json", sensitive}, 2},
		{[]string{"--log-json", "help", sensitive}, 2},
		{[]string{"--log-json", "init", "--output", "irrelevant.yaml"}, 1},
	}
	for _, tc := range cases {
		var out, diagnostics bytes.Buffer
		code := Run(context.Background(), tc.args, strings.NewReader(""), &out, &diagnostics)
		if code != tc.code {
			t.Fatalf("got exit code %d, want %d", code, tc.code)
		}
		if strings.Contains(out.String()+diagnostics.String(), sensitive) {
			t.Fatal("error exposed input")
		}
		checkLogs(t, diagnostics.String())
	}
}

func TestVersionAndHelp(t *testing.T) {
	for _, args := range [][]string{nil, {"--version"}, {"init", "--help"}, {"help", "preflight"}} {
		var out, diagnostics bytes.Buffer
		if code := Run(t.Context(), args, strings.NewReader(""), &out, &diagnostics); code != 0 || out.Len() == 0 || diagnostics.Len() != 0 {
			t.Fatal("expected help or version on stdout")
		}
	}
}

func checkLogs(t *testing.T, output string) {
	t.Helper()
	if output == "" {
		t.Fatal("expected structured diagnostics")
	}
	for line := range strings.SplitSeq(strings.TrimSuffix(output, "\n"), "\n") {
		var event struct {
			Message string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil || event.Message == "" {
			t.Fatal("expected one JSON event per line")
		}
	}
}
