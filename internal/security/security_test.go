package security

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPasswordHashAndVerify(t *testing.T) {
	hash, err := HashPassword("Correct-Horse-42!")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected argon2id encoding: %s", hash)
	}
	if !VerifyPassword(hash, "Correct-Horse-42!") {
		t.Fatal("expected password to verify")
	}
	if VerifyPassword(hash, "wrong-password") {
		t.Fatal("wrong password must not verify")
	}
}

func TestHashPasswordRejectsShortSecrets(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("expected short password to be rejected")
	}
}

func TestHashPasswordRejectsOversizedSecrets(t *testing.T) {
	long := strings.Repeat("A", MaxPasswordRunes+1)
	if _, err := HashPassword(long); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("oversized hash err=%v", err)
	}
	if _, err := HashPassword(strings.Repeat("A", MaxPasswordRunes)); err != nil {
		t.Fatalf("max password err=%v", err)
	}
}

func TestVerifyPasswordRejectsOversizedSecrets(t *testing.T) {
	hash, err := HashPassword("Correct-Horse-42!")
	if err != nil {
		t.Fatal(err)
	}
	if VerifyPassword(hash, strings.Repeat("A", MaxPasswordRunes+1)) {
		t.Fatal("oversized password must not verify")
	}
}

func TestLegacyShortPasswordCanBeUpgraded(t *testing.T) {
	hash, err := HashLegacyPassword("short")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "short") {
		t.Fatal("legacy short password should still verify during migration")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	if VerifyPassword("$argon2id$v=19$bad-params$salt$hash", "Correct-Horse-42!") {
		t.Fatal("malformed argon2id hash must not verify")
	}
}

func TestVerifyPasswordRejectsPlaintext(t *testing.T) {
	if VerifyPassword("Correct-Horse-42!", "Correct-Horse-42!") {
		t.Fatal("plaintext password material must not verify after migrate")
	}
	if IsArgon2id("Correct-Horse-42!") {
		t.Fatal("plaintext must not be reported as argon2id")
	}
}

func TestVerifyPasswordRejectsUnexpectedParameters(t *testing.T) {
	encoded := "$argon2id$v=19$m=8,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if VerifyPassword(encoded, "Correct-Horse-42!") {
		t.Fatal("unexpected argon2id parameters must not verify")
	}
	if IsCurrentPasswordHash(encoded) {
		t.Fatal("low-cost hash must not be treated as current")
	}
	if !IsArgon2id(encoded) {
		t.Fatal("PHC prefix must still be detected as argon2id")
	}
}

func TestIsCurrentPasswordHashAcceptsCanonicalEncoding(t *testing.T) {
	hash, err := HashPassword("Correct-Horse-42!")
	if err != nil {
		t.Fatal(err)
	}
	if !IsCurrentPasswordHash(hash) {
		t.Fatalf("canonical hash rejected: %s", hash)
	}
	if IsCurrentPasswordHash("$argon2id$v=19$m=65536,t=3,p=2$short$short") {
		t.Fatal("truncated hash must not be current")
	}
}

func TestCipherPersistsMasterKey(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateCipher(dir)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := first.Encrypt("sensitive-value")
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted(encrypted) {
		t.Fatal("ciphertext must use enc:v1 prefix")
	}
	second, err := LoadOrCreateCipher(dir)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := second.Decrypt(encrypted)
	if err != nil || plain != "sensitive-value" {
		t.Fatalf("decrypt = %q, %v", plain, err)
	}
	info, err := os.Stat(filepath.Join(dir, "master.key"))
	if err != nil || info.Size() == 0 {
		t.Fatal("master key was not persisted")
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("master key mode = %v", info.Mode().Perm())
	}
}

func TestCipherDoesNotReencryptOrLeakEmptyValues(t *testing.T) {
	cipher, err := LoadOrCreateCipher(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt("once")
	if err != nil {
		t.Fatal(err)
	}
	again, err := cipher.Encrypt(encrypted)
	if err != nil || again != encrypted {
		t.Fatalf("re-encrypt = %q, %v", again, err)
	}
	empty, err := cipher.Encrypt("")
	if err != nil || empty != "" {
		t.Fatalf("empty encrypt = %q, %v", empty, err)
	}
	plain, err := cipher.Decrypt("")
	if err != nil || plain != "" {
		t.Fatalf("empty decrypt = %q, %v", plain, err)
	}
}

func TestCipherRejectsTamperedValue(t *testing.T) {
	cipher, err := LoadOrCreateCipher(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt("sensitive-value")
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted(encrypted) {
		t.Fatalf("expected encrypted payload, got %q", encrypted)
	}
	// Corrupt a middle ciphertext character so AEAD authentication must fail.
	mid := len(encrypted)/2
	replacement := byte('A')
	if encrypted[mid] == replacement {
		replacement = 'B'
	}
	tampered := encrypted[:mid] + string(replacement) + encrypted[mid+1:]
	if _, err = cipher.Decrypt(tampered); err == nil {
		t.Fatal("tampered ciphertext must not decrypt")
	}
}

func TestCipherRejectsForeignMasterKey(t *testing.T) {
	first, err := LoadOrCreateCipher(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := first.Encrypt("sensitive-value")
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateCipher(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = second.Decrypt(encrypted); err == nil {
		t.Fatal("ciphertext must not decrypt under a different master key")
	}
}

func TestLoadOrCreateCipherAcceptsLegacyRawKey(t *testing.T) {
	dir := t.TempDir()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "master.key")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	cipher, err := LoadOrCreateCipher(dir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("legacy master key mode = %v err=%v", info.Mode().Perm(), err)
	}
	encrypted, err := cipher.Encrypt("legacy-raw-key")
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadOrCreateCipher(dir)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := reloaded.Decrypt(encrypted)
	if err != nil || plain != "legacy-raw-key" {
		t.Fatalf("decrypt = %q, %v", plain, err)
	}
}

func TestLoadOrCreateCipherRejectsShortKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "master.key"), []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCipher(dir); err == nil {
		t.Fatal("expected short master key file to be rejected")
	}
}

func TestTokenHashDoesNotContainToken(t *testing.T) {
	token, err := NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	hash := TokenHash(token)
	if hash == "" || hash == token || strings.Contains(hash, token) {
		t.Fatalf("token hash leaked the raw token: hash=%q token=%q", hash, token)
	}
	if TokenHash(token+"x") == hash {
		t.Fatal("distinct tokens must not share a hash")
	}
}

func TestEncryptAADRejectsFieldSwap(t *testing.T) {
	cipher, err := LoadOrCreateCipher(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.EncryptAAD("telegram-token-value", "notify_tg_token")
	if err != nil {
		t.Fatal(err)
	}
	if !IsBoundCiphertext(encrypted) {
		t.Fatalf("AAD ciphertext must use enc:v2: %q", encrypted)
	}
	plain, err := cipher.DecryptAAD(encrypted, "notify_tg_token")
	if err != nil || plain != "telegram-token-value" {
		t.Fatalf("roundtrip = %q err=%v", plain, err)
	}
	if _, err = cipher.DecryptAAD(encrypted, "notify_wh_secret"); err == nil {
		t.Fatal("ciphertext bound to telegram must not decrypt as webhook secret")
	}
	if _, err = cipher.Decrypt(encrypted); err == nil {
		t.Fatal("v2 ciphertext must not decrypt without AAD")
	}
}

func TestLegacyV1CiphertextStillDecrypts(t *testing.T) {
	cipher, err := LoadOrCreateCipher(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt("legacy-secret")
	if err != nil {
		t.Fatal(err)
	}
	if IsBoundCiphertext(encrypted) || !IsEncrypted(encrypted) {
		t.Fatalf("unbound encrypt must stay enc:v1: %q", encrypted)
	}
	plain, err := cipher.DecryptAAD(encrypted, "notify_tg_token")
	if err != nil || plain != "legacy-secret" {
		t.Fatalf("legacy v1 must still decrypt during migrate, got %q err=%v", plain, err)
	}
}
