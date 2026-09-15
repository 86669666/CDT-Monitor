package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	encryptedPrefix   = "enc:v1:"
	encryptedPrefixV2 = "enc:v2:"
	AccountSecretAAD  = "account_secret"
)

func AccountBoundAAD(accessKeyID string) string {
	return AccountSecretAAD + ":" + accessKeyID
}

type Cipher struct {
	aead cipher.AEAD
}

func LoadOrCreateCipher(dataDir string) (*Cipher, error) {
	path := filepath.Join(dataDir, "master.key")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key := make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate master key: %w", err)
		}
		if err = os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600); err != nil {
			return nil, fmt.Errorf("write master key: %w", err)
		}
		if err = restrictKeyFile(path); err != nil {
			return nil, err
		}
		return newCipher(key)
	}
	if err != nil {
		return nil, fmt.Errorf("read master key: %w", err)
	}
	if err = restrictKeyFile(path); err != nil {
		return nil, err
	}
	key, err := parseMasterKey(raw)
	if err != nil {
		return nil, err
	}
	return newCipher(key)
}

func restrictKeyFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict master key permissions: %w", err)
	}
	return nil
}

func parseMasterKey(raw []byte) ([]byte, error) {
	if decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw))); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if len(raw) == 32 {
		return raw, nil
	}
	return nil, fmt.Errorf("master key must contain 32 bytes")
}

func newCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must contain 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

func (c *Cipher) Encrypt(plaintext string) (string, error) {
	return c.encrypt(plaintext, nil)
}

func (c *Cipher) EncryptAAD(plaintext, aad string) (string, error) {
	return c.encrypt(plaintext, []byte(aad))
}

func (c *Cipher) encrypt(plaintext string, aad []byte) (string, error) {
	if plaintext == "" || IsEncrypted(plaintext) {
		return plaintext, nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plaintext), aad)
	prefix := encryptedPrefix
	if len(aad) > 0 {
		prefix = encryptedPrefixV2
	}
	return prefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (c *Cipher) Decrypt(value string) (string, error) {
	return c.decrypt(value, nil)
}

func (c *Cipher) DecryptAAD(value, aad string) (string, error) {
	return c.decrypt(value, []byte(aad))
}

func (c *Cipher) decrypt(value string, aad []byte) (string, error) {
	if value == "" {
		return "", nil
	}
	if strings.HasPrefix(value, encryptedPrefixV2) {
		return c.open(value, encryptedPrefixV2, aad)
	}
	if strings.HasPrefix(value, encryptedPrefix) {
		return c.open(value, encryptedPrefix, nil)
	}
	return value, nil
}

func (c *Cipher) open(value, prefix string, aad []byte) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || len(raw) < c.aead.NonceSize() {
		return "", errors.New("invalid encrypted value")
	}
	nonce, ciphertext := raw[:c.aead.NonceSize()], raw[c.aead.NonceSize():]
	plain, err := c.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return "", errors.New("unable to decrypt value with current master key")
	}
	return string(plain), nil
}

func IsEncrypted(value string) bool {
	return strings.HasPrefix(value, encryptedPrefix) || strings.HasPrefix(value, encryptedPrefixV2)
}

func IsBoundCiphertext(value string) bool {
	return strings.HasPrefix(value, encryptedPrefixV2)
}

func NewToken(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func HashPassword(password string) (string, error) {
	if len(password) < 10 {
		return "", errors.New("password must be at least 10 characters")
	}
	return hashPassword(password)
}

func HashLegacyPassword(password string) (string, error) {
	return hashPassword(password)
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	memory, iterations, parallelism, keyLen := uint32(64*1024), uint32(3), uint8(2), uint32(32)
	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func IsArgon2id(encoded string) bool {
	return strings.HasPrefix(encoded, "$argon2id$")
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
