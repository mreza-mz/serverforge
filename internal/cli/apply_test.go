package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyRejectsMissingOrInvalidApprovalBeforeLaunchingAnsible(t *testing.T) {
	work := t.TempDir()
	receipt := filepath.Join(work, "receipt.json")
	program := filepath.Join(work, "ansible-playbook")
	if err := os.WriteFile(receipt, []byte(`{"version":1,"plan_id":"wrong"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(program, []byte("#!/bin/sh\n: > \"${0%/*}/started\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", work)
	path := filepath.Join("..", "..", "examples", "local.yaml")
	for _, approval := range [][]string{nil, {"--approval", receipt}} {
		args := append([]string{"apply", "--config", path}, approval...)
		var out, stderr bytes.Buffer
		code := Run(t.Context(), args, strings.NewReader(""), &out, &stderr)
		if code != 1 || !strings.Contains(out.String(), "Execution plan") || strings.Contains(stderr.String(), "wrong") {
			t.Fatal("apply did not safely reject unapproved plan")
		}
		if _, err := os.Stat(filepath.Join(work, "started")); !os.IsNotExist(err) {
			t.Fatal("apply launched Ansible before checking approval")
		}
	}
}
