// Package vault encrypts secret mappings using the Ansible Vault file format.
package vault

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf8"

	ansiblevault "github.com/sosedoff/ansible-vault-go"
	"go.yaml.in/yaml/v3"
)

const header = "$ANSIBLE_VAULT;1.1;AES256"

func ValidatePassword(value string) error {
	if len(value) > 4096 || strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("enter a non-empty single-line password of at most 4096 bytes")
	}
	return nil
}

func ValidatePassphrase(value string) error {
	if ValidatePassword(value) != nil || value != strings.TrimSpace(value) || utf8.RuneCountInString(value) < 16 {
		return errors.New("use a Vault passphrase of at least 16 characters without surrounding whitespace")
	}
	return nil
}

func Encrypt(secrets map[string]string, passphrase string) (string, error) {
	if err := ValidatePassphrase(passphrase); err != nil {
		return "", err
	}
	if len(secrets) == 0 {
		return "", errors.New("no credentials to encrypt")
	}
	for _, secret := range secrets {
		if err := ValidatePassword(secret); err != nil {
			return "", err
		}
	}
	data, err := yaml.Marshal(secrets)
	if err != nil {
		return "", errors.New("could not encode credentials")
	}
	defer clear(data)

	ciphertext, err := ansiblevault.Encrypt(string(data), passphrase)
	if err != nil {
		return "", errors.New("could not encrypt credentials")
	}
	return ciphertext + "\n", nil
}

// Validate checks the Vault envelope without decrypting it.
func Validate(value string) error {
	invalid := errors.New("vault must contain an Ansible Vault 1.1 or 1.2 AES256 payload")
	line, body, found := strings.Cut(strings.TrimRight(value, "\r\n"), "\n")
	line = strings.TrimSuffix(line, "\r")
	label, labeled := strings.CutPrefix(line, "$ANSIBLE_VAULT;1.2;AES256;")
	validLabel := labeled && label != "" &&
		len(label) <= 128 && !strings.ContainsAny(label, "; \t\r\n")
	if !found || (line != header && !validLabel) {
		return invalid
	}
	raw, err := hex.DecodeString(strings.NewReplacer("\n", "", "\r", "").Replace(body))
	if err != nil {
		return invalid
	}
	parts := strings.Split(string(raw), "\n")
	if len(parts) != 3 {
		return invalid
	}
	salt, saltErr := hex.DecodeString(parts[0])
	digest, digestErr := hex.DecodeString(parts[1])
	ciphertext, cipherErr := hex.DecodeString(parts[2])
	if saltErr != nil || digestErr != nil || cipherErr != nil ||
		len(salt) != sha256.Size || len(digest) != sha256.Size ||
		len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return invalid
	}
	return nil
}
