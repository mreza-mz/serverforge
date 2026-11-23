package provision

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/mreza-mz/serverforge/internal/config"
	"github.com/mreza-mz/serverforge/internal/vault"
	"github.com/xdg-go/stringprep"
)

func credentials(profile config.Profile, passphrase string) (map[string]string, error) {
	verifiers := make(map[string]string)
	if profile.Vault == "" {
		return verifiers, nil
	}
	var keys []string
	for _, engine := range config.DatabaseModules() {
		if _, selected := profile.Databases[engine.Module]; selected {
			keys = append(keys, engine.Module.PasswordKey())
		}
	}
	if profile.Redis != nil {
		keys = append(keys, config.Redis.PasswordKey())
	}
	passwords, err := vault.Decrypt(profile.Vault, passphrase, keys)
	if err != nil {
		return nil, err
	}
	defer clear(passwords)
	for _, key := range keys {
		password := passwords[key]
		// The Vault's random salt makes this deterministic salt unique to a
		// credential payload and stable across retries of the same profile.
		salt := sha256.Sum256([]byte(key + "\n" + profile.Vault))
		switch key {
		case config.PostgreSQL.PasswordKey():
			verifiers[string(config.PostgreSQL)], err = postgresVerifier(password, salt[:16])
			if err != nil {
				return nil, err
			}
		case config.MySQL.PasswordKey():
			if len(password) > 256 {
				return nil, errors.New("MySQL password must be at most 256 bytes")
			}
			verifiers[string(config.MySQL)] = mysqlVerifier(password, hex.EncodeToString(salt[:10]))
		case config.MariaDB.PasswordKey():
			first := sha1.Sum([]byte(password)) // MariaDB mysql_native_password format.
			second := sha1.Sum(first[:])
			verifiers[string(config.MariaDB)] = "*" + strings.ToUpper(hex.EncodeToString(second[:]))
		case config.Redis.PasswordKey():
			sum := sha256.Sum256([]byte(password))
			verifiers[string(config.Redis)] = hex.EncodeToString(sum[:])
		}
	}
	return verifiers, nil
}

func postgresVerifier(password string, salt []byte) (string, error) {
	if normalized, err := stringprep.SASLprep.Prepare(password); err == nil {
		password = normalized
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, 4096, sha256.Size)
	if err != nil {
		return "", errors.New("could not derive PostgreSQL credential")
	}
	defer clear(salted)
	digest := func(label string) []byte {
		mac := hmac.New(sha256.New, salted)
		mac.Write([]byte(label))
		return mac.Sum(nil)
	}
	stored := sha256.Sum256(digest("Client Key"))
	b64 := base64.StdEncoding.EncodeToString
	return "SCRAM-SHA-256$4096:" + b64(salt) + "$" + b64(stored[:]) + ":" + b64(digest("Server Key")), nil
}

// mysqlVerifier implements the SHA-256 crypt format used by MySQL's
// caching_sha2_password, which uses a 20-byte salt and 5000 rounds.
func mysqlVerifier(password, salt string) string {
	alternate := sha256.Sum256([]byte(password + salt + password))
	repeat := func(sum []byte, size int) []byte {
		buffer := make([]byte, size)
		for offset := 0; offset < size; {
			offset += copy(buffer[offset:], sum)
		}
		return buffer
	}
	hash := sha256.New()
	hash.Write([]byte(password + salt))
	hash.Write(repeat(alternate[:], len(password)))
	for length := len(password); length > 0; length >>= 1 {
		if length&1 == 1 {
			hash.Write(alternate[:])
		} else {
			hash.Write([]byte(password))
		}
	}
	digest := hash.Sum(nil)
	pwSum := sha256.Sum256([]byte(strings.Repeat(password, len(password))))
	saltSum := sha256.Sum256([]byte(strings.Repeat(salt, 16+int(digest[0]))))
	pwBytes, saltBytes := repeat(pwSum[:], len(password)), saltSum[:len(salt)]
	for round := 0; round < 5000; round++ {
		hash.Reset()
		if round%2 == 0 {
			hash.Write(digest)
		} else {
			hash.Write(pwBytes)
		}
		if round%3 != 0 {
			hash.Write(saltBytes)
		}
		if round%7 != 0 {
			hash.Write(pwBytes)
		}
		if round%2 == 0 {
			hash.Write(pwBytes)
		} else {
			hash.Write(digest)
		}
		digest = hash.Sum(digest[:0])
	}
	const alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var encoded strings.Builder
	encode := func(high, middle, low byte, count int) {
		value := int(high)<<16 | int(middle)<<8 | int(low)
		for range count {
			encoded.WriteByte(alphabet[value&63])
			value >>= 6
		}
	}
	for i := range 10 {
		encode(digest[(i*21)%30], digest[(i*21+10)%30], digest[(i*21+20)%30], 4)
	}
	encode(0, digest[31], digest[30], 3)
	return "$A$005$" + salt + encoded.String()
}
