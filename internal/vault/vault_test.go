package vault

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ansiblevault "github.com/sosedoff/ansible-vault-go"
	"go.yaml.in/yaml/v3"
)

const testPassphrase = "test-passphrase-only-for-ci"
const testPassword = "test! password: 密碼 #"

func TestEncrypt(t *testing.T) {
	payload := map[string]string{"postgresql_password": testPassword}
	first, err := Encrypt(payload, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Encrypt(payload, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || strings.Contains(first, testPassword) || strings.Contains(first, testPassphrase) {
		t.Fatal("ciphertext reused or exposed plaintext")
	}
	if err := Validate(first); err != nil {
		t.Fatal(err)
	}
	plaintext, err := ansiblevault.Decrypt(first, testPassphrase)
	if err != nil {
		t.Fatal("could not decrypt test data")
	}
	assertPayload(t, []byte(plaintext))
}

func TestValidateVault(t *testing.T) {
	good, err := Encrypt(map[string]string{"postgresql_password": testPassword}, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	for _, valid := range []string{good, strings.Replace(good, header, "$ANSIBLE_VAULT;1.2;AES256;production", 1)} {
		if err := Validate(valid); err != nil {
			t.Fatal(err)
		}
	}
	for _, invalid := range []string{
		"", "plaintext", header, header + "\nnot-hex", header + "\n0010", strings.TrimRight(good, "\n") + "ff",
		strings.Replace(good, header, "$ANSIBLE_VAULT;1.2;AES256;", 1),
		strings.Replace(good, "AES256", "not-a-cipher", 1),
	} {
		if Validate(invalid) == nil {
			t.Fatal("invalid vault passed validation")
		}
	}
}

func TestRejectEmptySecretsAndWeakPassphrases(t *testing.T) {
	if _, err := Encrypt(nil, testPassphrase); err == nil {
		t.Fatal("expected missing credentials error")
	}
	for _, invalid := range []string{"", "short", " leading-whitespace", "embedded\nnewline-passphrase"} {
		if _, err := Encrypt(map[string]string{"redis_password": testPassword}, invalid); err == nil {
			t.Fatal("accepted an invalid Vault passphrase")
		}
	}
	for _, invalid := range []string{"  ", "a\nb", "a\x00b", strings.Repeat("x", 4097)} {
		if _, err := Encrypt(map[string]string{"redis_password": invalid}, testPassphrase); err == nil {
			t.Fatal("accepted an invalid service password")
		}
	}
}

func TestAnsibleVaultInterop(t *testing.T) {
	binary, err := exec.LookPath("ansible-vault")
	if err != nil {
		if os.Getenv("SERVERFORGE_REQUIRE_ANSIBLE_VAULT") == "1" {
			t.Fatal("ansible-vault is required for the interoperability test")
		}
		t.Skip("install ansible-vault to run the interoperability test")
	}
	dir := t.TempDir()
	cmd := exec.Command(binary, "decrypt", "--vault-password-file", "/dev/stdin", "--output", "-", "credentials.vault")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+dir)
	cmd.Stdin = strings.NewReader(testPassphrase + "\n")
	ciphertext, err := Encrypt(map[string]string{"postgresql_password": testPassword}, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "credentials.vault"), []byte(ciphertext), 0600); err != nil {
		t.Fatal(err)
	}
	plaintext, err := cmd.Output()
	if err != nil {
		t.Fatal("ansible-vault could not decrypt ServerForge ciphertext")
	}
	assertPayload(t, plaintext)
}

func assertPayload(t *testing.T, plaintext []byte) {
	t.Helper()
	var secrets map[string]string
	if err := yaml.Unmarshal(plaintext, &secrets); err != nil ||
		len(secrets) != 1 || secrets["postgresql_password"] != testPassword {
		t.Fatal("unexpected decrypted test credentials")
	}
}
