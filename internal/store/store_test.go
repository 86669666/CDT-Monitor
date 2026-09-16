package store

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/security"
	_ "modernc.org/sqlite"
)

func TestMigratesLegacySecretsAndPassword(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", dir+"/data.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, access_key_id TEXT, access_key_secret TEXT, region_id TEXT, instance_id TEXT, max_traffic REAL, schedule_enabled INTEGER DEFAULT 0, start_time TEXT, stop_time TEXT, traffic_used REAL DEFAULT 0, instance_status TEXT DEFAULT 'Unknown', updated_at INTEGER DEFAULT 0, last_keep_alive_at INTEGER DEFAULT 0);
INSERT INTO settings(key,value) VALUES('admin_password','legacy-password'),('notify_tg_token','legacy-token'),('notify_wh_secret','legacy-webhook-secret'),('notify_wh_url','https://example.test/hook?access_token=legacy-url-token'),('notify_wh_body','{"access_token":"legacy-body-token"}');
INSERT INTO accounts(access_key_id,access_key_secret,region_id,instance_id,max_traffic) VALUES('LTAIlegacy','legacy-secret','cn-hongkong','i-legacy',200);
`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var token, secret, webhook string
	if err = st.db.QueryRow(`SELECT value FROM settings WHERE key='notify_tg_token'`).Scan(&token); err != nil {
		t.Fatal(err)
	}
	if err = st.db.QueryRow(`SELECT value FROM settings WHERE key='notify_wh_secret'`).Scan(&webhook); err != nil {
		t.Fatal(err)
	}
	var webhookURL, webhookBody string
	if err = st.db.QueryRow(`SELECT value FROM settings WHERE key='notify_wh_url'`).Scan(&webhookURL); err != nil {
		t.Fatal(err)
	}
	if err = st.db.QueryRow(`SELECT value FROM settings WHERE key='notify_wh_body'`).Scan(&webhookBody); err != nil {
		t.Fatal(err)
	}
	if err = st.db.QueryRow(`SELECT access_key_secret FROM accounts WHERE id=1`).Scan(&secret); err != nil {
		t.Fatal(err)
	}
	if !security.IsBoundCiphertext(token) || !security.IsBoundCiphertext(webhook) || !security.IsBoundCiphertext(webhookURL) || !security.IsBoundCiphertext(webhookBody) || !security.IsBoundCiphertext(secret) {
		t.Fatal("legacy secrets were not bound to field AAD")
	}
	if strings.Contains(webhookURL, "legacy-url-token") {
		t.Fatalf("webhook URL stored in plaintext: %q", webhookURL)
	}
	if strings.Contains(webhookBody, "legacy-body-token") {
		t.Fatalf("webhook body stored in plaintext: %q", webhookBody)
	}
	telegram, err := st.DecryptAAD(token, "notify_tg_token")
	if err != nil || telegram != "legacy-token" {
		t.Fatalf("telegram token = %q err=%v", telegram, err)
	}
	webhookPlain, err := st.DecryptAAD(webhook, "notify_wh_secret")
	if err != nil || webhookPlain != "legacy-webhook-secret" {
		t.Fatalf("webhook secret = %q err=%v", webhookPlain, err)
	}
	urlPlain, err := st.DecryptAAD(webhookURL, "notify_wh_url")
	if err != nil || urlPlain != "https://example.test/hook?access_token=legacy-url-token" {
		t.Fatalf("webhook url = %q err=%v", urlPlain, err)
	}
	bodyPlain, err := st.DecryptAAD(webhookBody, "notify_wh_body")
	if err != nil || bodyPlain != `{"access_token":"legacy-body-token"}` {
		t.Fatalf("webhook body = %q err=%v", bodyPlain, err)
	}
	storedSecret, err := st.AccountSecret(context.Background(), 1)
	if err != nil || storedSecret != "legacy-secret" {
		t.Fatalf("account secret = %q err=%v", storedSecret, err)
	}
	var hash string
	if err = st.db.QueryRow(`SELECT value FROM settings WHERE key='admin_password'`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if !security.IsCurrentPasswordHash(hash) || hash == "legacy-password" {
		t.Fatalf("legacy password was not upgraded during migrate: %q", hash)
	}
	valid, err := st.VerifyAdminPassword(context.Background(), "legacy-password")
	if err != nil || !valid {
		t.Fatalf("legacy password failed: %v", err)
	}
}

func TestCorruptAdminPasswordHashIsRejected(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}}}
	if err = st.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.Exec(`UPDATE settings SET value='not-argon2id' WHERE key='admin_password'`); err != nil {
		t.Fatal(err)
	}
	valid, err := st.VerifyAdminPassword(context.Background(), "not-argon2id")
	if err != nil || valid {
		t.Fatalf("corrupt hash must fail closed, valid=%v err=%v", valid, err)
	}
	valid, err = st.VerifyAdminPassword(context.Background(), "Strong-Password-42!")
	if err != nil || valid {
		t.Fatalf("original password must not verify a corrupt hash, valid=%v err=%v", valid, err)
	}
}

func TestSetupRejectsOversizedAdminPassword(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	config := domain.Config{AdminPassword: strings.Repeat("A", security.MaxPasswordRunes+1), TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}}}
	if err = st.Setup(context.Background(), config); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("setup err=%v", err)
	}
}

func TestOpenRejectsUnsupportedArgon2idParams(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}}}
	if err = st.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if err = st.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "data.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE settings SET value='$argon2id$v=19$m=8,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' WHERE key='admin_password'`); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(dir); err == nil || !strings.Contains(err.Error(), "supported argon2id encoding") {
		t.Fatalf("unsupported hash must fail closed on open, err=%v", err)
	}
}

func TestSaveConfigDoesNotKeepUnsupportedPasswordHash(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}}}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	injected := "$argon2id$v=19$m=8,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	config.AdminPassword = injected
	config.Accounts[0].AccessKeySecret = ""
	if err = st.SaveConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err = st.db.QueryRow(`SELECT value FROM settings WHERE key='admin_password'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == injected || !security.IsCurrentPasswordHash(stored) {
		t.Fatalf("unsupported hash was stored: %q", stored)
	}
	valid, err := st.VerifyAdminPassword(ctx, injected)
	if err != nil || !valid {
		t.Fatalf("injected hash string should be hashed as a new password, valid=%v err=%v", valid, err)
	}
	valid, err = st.VerifyAdminPassword(ctx, "Strong-Password-42!")
	if err != nil || valid {
		t.Fatalf("original password must not verify after replacement, valid=%v err=%v", valid, err)
	}
}

func TestAccountIDsRemainStable(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}}}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	accounts, _ := st.ListAccounts(ctx)
	id := accounts[0].ID
	if accounts[0].AccessKeySecret != "" || !accounts[0].SecretConfigured {
		t.Fatal("list accounts must not include access key secret")
	}
	config.AdminPassword = ""
	config.Accounts[0].ID = id
	config.Accounts[0].AccessKeySecret = ""
	config.Accounts[0].Remark = "updated"
	if err = st.SaveConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
	accounts, _ = st.ListAccounts(ctx)
	if accounts[0].ID != id || accounts[0].Remark != "updated" {
		t.Fatal("account ID was not stable")
	}
}

func TestSaveConfigRejectsOversizedAccessKeySecret(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}}}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	config.AdminPassword = ""
	config.Accounts[0].AccessKeySecret = strings.Repeat("s", maxAccessKeySecretRunes+1)
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "access_key_secret is too long") {
		t.Fatalf("secret err=%v", err)
	}
	config.Accounts[0].AccessKeySecret = strings.Repeat("s", maxAccessKeySecretRunes)
	if err = st.SaveConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
}

func TestSaveConfigRejectsOversizedAccountRemark(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}}}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	config.AdminPassword = ""
	config.Accounts[0].AccessKeySecret = ""
	config.Accounts[0].Remark = strings.Repeat("备", maxAccountRemarkRunes+1)
	if err = st.SaveConfig(ctx, config); err == nil {
		t.Fatal("expected oversized remark to be rejected")
	}
	config.Accounts[0].Remark = strings.Repeat("备", maxAccountRemarkRunes)
	if err = st.SaveConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
	accounts, err := st.ListAccounts(ctx)
	if err != nil || len(accounts) != 1 || accounts[0].Remark != strings.Repeat("备", maxAccountRemarkRunes) {
		t.Fatalf("accounts=%#v err=%v", accounts, err)
	}
}

func TestSaveConfigRejectsMalformedAccountIdentifiers(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}}}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	config.AdminPassword = ""
	config.Accounts[0].AccessKeySecret = ""
	config.Accounts[0].RegionID = "cn-hongkong.evil.com"
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "region_id is invalid") {
		t.Fatalf("dotted region err=%v", err)
	}
	config.Accounts[0].RegionID = "cn-hongkong"
	config.Accounts[0].AccessKeyID = "LTAI/test"
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "access_key_id is invalid") {
		t.Fatalf("access key err=%v", err)
	}
	config.Accounts[0].AccessKeyID = "LTAItest"
	config.Accounts[0].InstanceID = "i-test.evil"
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "instance_id is invalid") {
		t.Fatalf("instance err=%v", err)
	}
	config.Accounts[0].InstanceID = "i-test"
	if err = st.SaveConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
}

func TestSaveConfigRejectsInvalidScheduleClock(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}}}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	config.AdminPassword = ""
	config.Accounts[0].AccessKeySecret = ""
	for _, clock := range []string{"9:00", "24:00", "15:04:05", "noon"} {
		config.Accounts[0].StartTime = clock
		config.Accounts[0].StopTime = "18:00"
		if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "schedule time is invalid") {
			t.Fatalf("start %q err=%v", clock, err)
		}
	}
	config.Accounts[0].StartTime = "08:30"
	config.Accounts[0].StopTime = "23:45"
	if err = st.SaveConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
	accounts, err := st.ListAccounts(ctx)
	if err != nil || accounts[0].StartTime != "08:30" || accounts[0].StopTime != "23:45" {
		t.Fatalf("accounts=%#v err=%v", accounts, err)
	}
}

func TestSaveConfigRejectsInvalidMaxTraffic(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}}}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	config.AdminPassword = ""
	config.Accounts[0].AccessKeySecret = ""
	for _, value := range []float64{0, -1, math.NaN(), math.Inf(1), maxAccountTrafficGB + 1} {
		config.Accounts[0].MaxTraffic = value
		if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "max traffic is invalid") {
			t.Fatalf("max traffic %v err=%v", value, err)
		}
	}
	config.Accounts[0].MaxTraffic = 512.5
	if err = st.SaveConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
}

func TestSaveConfigRejectsTooManyAccounts(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	accounts := make([]domain.Account, maxAccounts+1)
	for i := range accounts {
		accounts[i] = domain.Account{AccessKeyID: "LTAI" + strings.Repeat("x", 4) + strconv.Itoa(i), AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}
	}
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: accounts}
	if err = st.Setup(ctx, config); err == nil || !strings.Contains(err.Error(), "too many accounts") {
		t.Fatalf("setup err=%v", err)
	}
	config.Accounts = accounts[:maxAccounts]
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
}

func TestSaveConfigRejectsInvalidNotifyPorts(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}}}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	config.AdminPassword = ""
	config.Accounts[0].AccessKeySecret = ""
	config.Notifications.Email.Port = 65536
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "notification port is invalid") {
		t.Fatalf("smtp port err=%v", err)
	}
	config.Notifications.Email.Port = 465
	config.Notifications.Telegram.ProxyPort = "0"
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "notification port is invalid") {
		t.Fatalf("proxy port 0 err=%v", err)
	}
	config.Notifications.Telegram.ProxyPort = "1080"
	if err = st.SaveConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
}

func TestSaveConfigRejectsInvalidNotifyOptions(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}}}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	config.AdminPassword = ""
	config.Accounts[0].AccessKeySecret = ""
	config.Notifications.Webhook.Method = "DELETE"
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "notification option is invalid") {
		t.Fatalf("method err=%v", err)
	}
	config.Notifications.Webhook.Method = "POST"
	config.Notifications.Email.Security = "none"
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "notification option is invalid") {
		t.Fatalf("security err=%v", err)
	}
	config.Notifications.Email.Security = "starttls"
	config.Notifications.Telegram.ProxyType = "http"
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "notification option is invalid") {
		t.Fatalf("proxy type err=%v", err)
	}
	config.Notifications.Telegram.ProxyType = "custom"
	if err = st.SaveConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
}

func TestSaveConfigRejectsNotifyHeaderInjection(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}}}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	config.AdminPassword = ""
	config.Accounts[0].AccessKeySecret = ""
	config.Notifications.Email.To = "ops@example.test\r\nBcc: attacker@evil.test"
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "line breaks") {
		t.Fatalf("email to injection err=%v", err)
	}
	config.Notifications.Email.To = "ops@example.test"
	config.Notifications.Webhook.Headers = "{\"X-Auth\":\"leak\\r\\nX-Injected: 1\"}"
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "line breaks") {
		t.Fatalf("webhook header injection err=%v", err)
	}
}

func TestSaveConfigRejectsOversizedNotifyIdentity(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}}}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	config.AdminPassword = ""
	config.Accounts[0].AccessKeySecret = ""
	config.Notifications.Email.To = strings.Repeat("a", 255)
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "identity is too long") {
		t.Fatalf("email to err=%v", err)
	}
	config.Notifications.Email.To = "ops@example.test"
	config.Notifications.Telegram.ChatID = strings.Repeat("9", 65)
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "identity is too long") {
		t.Fatalf("chat id err=%v", err)
	}
	config.Notifications.Telegram.ChatID = ""
	config.Notifications.Telegram.ProxyUser = strings.Repeat("u", 256)
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "identity is too long") {
		t.Fatalf("proxy user err=%v", err)
	}
}

func TestSaveConfigRejectsOversizedWebhookPayload(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}}}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	config.AdminPassword = ""
	config.Accounts[0].AccessKeySecret = ""
	config.Notifications.Webhook.Body = strings.Repeat("x", 8193)
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "payload is too long") {
		t.Fatalf("body err=%v", err)
	}
	config.Notifications.Webhook.Body = ""
	config.Notifications.Webhook.Headers = strings.Repeat("h", 4097)
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "payload is too long") {
		t.Fatalf("headers err=%v", err)
	}
	config.Notifications.Webhook.Headers = ""
	config.Notifications.Webhook.URL = "https://example.test/" + strings.Repeat("x", 2048)
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "payload is too long") {
		t.Fatalf("url err=%v", err)
	}
}

func TestWebhookHeadersStayUntilCleared(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{
		AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging",
		ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai",
		Accounts:      []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}},
		Notifications: domain.NotificationConfig{Webhook: domain.WebhookConfig{URL: "https://example.test/hook", Headers: `{"X-Auth":"leak-me"}`, Secret: "webhook-secret-value"}},
	}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	loaded, err := st.GetConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Notifications.Webhook.HeadersConfigured || !loaded.Notifications.Webhook.SecretConfigured {
		t.Fatalf("configured flags = %#v", loaded.Notifications.Webhook)
	}
	if loaded.Notifications.Webhook.Headers != `{"X-Auth":"leak-me"}` || loaded.Notifications.Webhook.Secret != "webhook-secret-value" {
		t.Fatalf("loaded webhook = %#v", loaded.Notifications.Webhook)
	}
	loaded.AdminPassword = ""
	loaded.Accounts[0].AccessKeySecret = ""
	loaded.Notifications.Webhook.Headers = ""
	loaded.Notifications.Webhook.Secret = ""
	if err = st.SaveConfig(ctx, loaded); err != nil {
		t.Fatal(err)
	}
	kept, err := st.GetConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if kept.Notifications.Webhook.Headers != `{"X-Auth":"leak-me"}` || kept.Notifications.Webhook.Secret != "webhook-secret-value" {
		t.Fatalf("empty save must keep webhook secrets: %#v", kept.Notifications.Webhook)
	}
	kept.AdminPassword = ""
	kept.Accounts[0].AccessKeySecret = ""
	kept.Notifications.Webhook.Headers = domain.ClearSecretSentinel
	kept.Notifications.Webhook.Secret = domain.ClearSecretSentinel
	if err = st.SaveConfig(ctx, kept); err != nil {
		t.Fatal(err)
	}
	cleared, err := st.GetConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cleared.Notifications.Webhook.HeadersConfigured || cleared.Notifications.Webhook.SecretConfigured || cleared.Notifications.Webhook.Headers != "" || cleared.Notifications.Webhook.Secret != "" {
		t.Fatalf("cleared webhook = %#v", cleared.Notifications.Webhook)
	}
}

func TestWebhookURLIsEncryptedAtRestAndClearable(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	endpoint := "https://example.test/hook?access_token=url-token-value"
	config := domain.Config{
		AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging",
		ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai",
		Accounts:      []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}},
		Notifications: domain.NotificationConfig{Webhook: domain.WebhookConfig{URL: endpoint}},
	}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err = st.db.QueryRow(`SELECT value FROM settings WHERE key='notify_wh_url'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !security.IsEncrypted(stored) || strings.Contains(stored, "url-token-value") {
		t.Fatalf("webhook URL must be encrypted at rest: %q", stored)
	}
	loaded, err := st.GetConfig(ctx)
	if err != nil || loaded.Notifications.Webhook.URL != endpoint || !loaded.Notifications.Webhook.URLConfigured {
		t.Fatalf("decrypted webhook URL = %#v err=%v", loaded.Notifications.Webhook, err)
	}
	loaded.AdminPassword = ""
	loaded.Accounts[0].AccessKeySecret = ""
	loaded.Notifications.Webhook.URL = ""
	if err = st.SaveConfig(ctx, loaded); err != nil {
		t.Fatal(err)
	}
	kept, err := st.GetConfig(ctx)
	if err != nil || kept.Notifications.Webhook.URL != endpoint || !kept.Notifications.Webhook.URLConfigured {
		t.Fatalf("empty URL must keep stored endpoint: %#v err=%v", kept.Notifications.Webhook, err)
	}
	kept.AdminPassword = ""
	kept.Accounts[0].AccessKeySecret = ""
	kept.Notifications.Webhook.URL = domain.ClearSecretSentinel
	if err = st.SaveConfig(ctx, kept); err != nil {
		t.Fatal(err)
	}
	cleared, err := st.GetConfig(ctx)
	if err != nil || cleared.Notifications.Webhook.URL != "" || cleared.Notifications.Webhook.URLConfigured {
		t.Fatalf("sentinel must clear stored endpoint: %#v err=%v", cleared.Notifications.Webhook, err)
	}
}

func TestWebhookBodyIsEncryptedAtRestAndClearable(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	template := `{"msgtype":"text","text":{"content":"token=body-token-value"}}`
	config := domain.Config{
		AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging",
		ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai",
		Accounts:      []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}},
		Notifications: domain.NotificationConfig{Webhook: domain.WebhookConfig{Body: template}},
	}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err = st.db.QueryRow(`SELECT value FROM settings WHERE key='notify_wh_body'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !security.IsEncrypted(stored) || strings.Contains(stored, "body-token-value") {
		t.Fatalf("webhook body must be encrypted at rest: %q", stored)
	}
	loaded, err := st.GetConfig(ctx)
	if err != nil || loaded.Notifications.Webhook.Body != template || !loaded.Notifications.Webhook.BodyConfigured {
		t.Fatalf("decrypted webhook body = %#v err=%v", loaded.Notifications.Webhook, err)
	}
	loaded.AdminPassword = ""
	loaded.Accounts[0].AccessKeySecret = ""
	loaded.Notifications.Webhook.Body = ""
	if err = st.SaveConfig(ctx, loaded); err != nil {
		t.Fatal(err)
	}
	kept, err := st.GetConfig(ctx)
	if err != nil || kept.Notifications.Webhook.Body != template || !kept.Notifications.Webhook.BodyConfigured {
		t.Fatalf("empty body must keep stored template: %#v err=%v", kept.Notifications.Webhook, err)
	}
	kept.AdminPassword = ""
	kept.Accounts[0].AccessKeySecret = ""
	kept.Notifications.Webhook.Body = domain.ClearSecretSentinel
	if err = st.SaveConfig(ctx, kept); err != nil {
		t.Fatal(err)
	}
	cleared, err := st.GetConfig(ctx)
	if err != nil || cleared.Notifications.Webhook.Body != "" || cleared.Notifications.Webhook.BodyConfigured {
		t.Fatalf("sentinel must clear stored body: %#v err=%v", cleared.Notifications.Webhook, err)
	}
}

func TestTelegramProxyURLIsEncryptedAtRestAndClearable(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	endpoint := "socks5://user:proxy-pass-value@127.0.0.1:1080"
	config := domain.Config{
		AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging",
		ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai",
		Accounts:      []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}},
		Notifications: domain.NotificationConfig{Telegram: domain.TelegramConfig{ProxyType: "socks5", ProxyURL: endpoint}},
	}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err = st.db.QueryRow(`SELECT value FROM settings WHERE key='notify_tg_proxy_url'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !security.IsBoundCiphertext(stored) || strings.Contains(stored, "proxy-pass-value") {
		t.Fatalf("telegram proxy URL must be encrypted at rest: %q", stored)
	}
	loaded, err := st.GetConfig(ctx)
	if err != nil || loaded.Notifications.Telegram.ProxyURL != endpoint || !loaded.Notifications.Telegram.ProxyURLConfigured {
		t.Fatalf("decrypted proxy URL = %#v err=%v", loaded.Notifications.Telegram, err)
	}
	loaded.AdminPassword = ""
	loaded.Accounts[0].AccessKeySecret = ""
	loaded.Notifications.Telegram.ProxyURL = ""
	if err = st.SaveConfig(ctx, loaded); err != nil {
		t.Fatal(err)
	}
	kept, err := st.GetConfig(ctx)
	if err != nil || kept.Notifications.Telegram.ProxyURL != endpoint || !kept.Notifications.Telegram.ProxyURLConfigured {
		t.Fatalf("empty proxy URL must keep stored endpoint: %#v err=%v", kept.Notifications.Telegram, err)
	}
	kept.AdminPassword = ""
	kept.Accounts[0].AccessKeySecret = ""
	kept.Notifications.Telegram.ProxyURL = domain.ClearSecretSentinel
	if err = st.SaveConfig(ctx, kept); err != nil {
		t.Fatal(err)
	}
	cleared, err := st.GetConfig(ctx)
	if err != nil || cleared.Notifications.Telegram.ProxyURL != "" || cleared.Notifications.Telegram.ProxyURLConfigured {
		t.Fatalf("sentinel must clear proxy URL: %#v err=%v", cleared.Notifications.Telegram, err)
	}
}

func TestCiphertextCannotBeSwappedBetweenSettings(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{
		AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging",
		ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai",
		Accounts: []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}},
		Notifications: domain.NotificationConfig{
			Telegram: domain.TelegramConfig{Token: "telegram-token-value"},
			Webhook:  domain.WebhookConfig{Secret: "webhook-secret-value"},
		},
	}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	var token, secret string
	if err = st.db.QueryRow(`SELECT value FROM settings WHERE key='notify_tg_token'`).Scan(&token); err != nil {
		t.Fatal(err)
	}
	if err = st.db.QueryRow(`SELECT value FROM settings WHERE key='notify_wh_secret'`).Scan(&secret); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.Exec(`UPDATE settings SET value=? WHERE key='notify_tg_token'`, secret); err != nil {
		t.Fatal(err)
	}
	if _, err = st.GetConfig(ctx); err == nil {
		t.Fatal("swapped webhook ciphertext must not decrypt as telegram token")
	}
}

func TestAccountSecretCannotBeSwappedBetweenAccounts(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{
		AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging",
		ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai",
		Accounts: []domain.Account{
			{AccessKeyID: "LTAIone", AccessKeySecret: "secret-one", RegionID: "cn-hongkong", InstanceID: "i-one", MaxTraffic: 200, SiteType: "china"},
			{AccessKeyID: "LTAItwo", AccessKeySecret: "secret-two", RegionID: "cn-hongkong", InstanceID: "i-two", MaxTraffic: 200, SiteType: "china"},
		},
	}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	accounts, err := st.ListAccounts(ctx)
	if err != nil || len(accounts) != 2 {
		t.Fatalf("accounts=%v err=%v", accounts, err)
	}
	var oneBlob, twoBlob string
	if err = st.db.QueryRow(`SELECT access_key_secret FROM accounts WHERE id=?`, accounts[0].ID).Scan(&oneBlob); err != nil {
		t.Fatal(err)
	}
	if err = st.db.QueryRow(`SELECT access_key_secret FROM accounts WHERE id=?`, accounts[1].ID).Scan(&twoBlob); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.Exec(`UPDATE accounts SET access_key_secret=? WHERE id=?`, oneBlob, accounts[1].ID); err != nil {
		t.Fatal(err)
	}
	listed, err := st.ListAccounts(ctx)
	if err != nil || len(listed) != 2 {
		t.Fatalf("list after swap accounts=%v err=%v", listed, err)
	}
	if !listed[0].SecretConfigured || !listed[1].SecretConfigured {
		t.Fatalf("list must not decrypt secrets to report configured: %#v", listed)
	}
	if listed[0].AccessKeySecret != "" || listed[1].AccessKeySecret != "" {
		t.Fatalf("list leaked decrypted secrets: %#v", listed)
	}
	if _, err = st.AccountSecret(ctx, accounts[1].ID); err == nil {
		t.Fatal("copied account ciphertext must not decrypt under a different access key")
	}
	got, err := st.AccountSecret(ctx, accounts[0].ID)
	if err != nil || got != "secret-one" {
		t.Fatalf("original account secret = %q err=%v", got, err)
	}
	secrets, err := st.AccountSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 || secrets[0] != "secret-one" {
		t.Fatalf("undecryptable swapped secret must be skipped: %#v", secrets)
	}
	listed, err = st.ListAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if listed[0].AccessKeySecret != "" || listed[1].AccessKeySecret != "" {
		t.Fatalf("AccountSecrets must not attach plaintext to list results: %#v", listed)
	}
	_ = twoBlob
}

func TestAccountSecretsIncludesDeletedAccounts(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{
		AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai",
		Accounts: []domain.Account{
			{AccessKeyID: "LTAIkeep", AccessKeySecret: "keep-secret-value", RegionID: "cn-hongkong", InstanceID: "i-keep", MaxTraffic: 200, SiteType: "china"},
			{AccessKeyID: "LTAIgone", AccessKeySecret: "gone-secret-value", RegionID: "cn-hongkong", InstanceID: "i-gone", MaxTraffic: 200, SiteType: "china"},
		},
	}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	config.Accounts = config.Accounts[:1]
	if err = st.SaveConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
	listed, err := st.ListAccounts(ctx)
	if err != nil || len(listed) != 1 || listed[0].AccessKeySecret != "" {
		t.Fatalf("active list=%#v err=%v", listed, err)
	}
	secrets, err := st.AccountSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(secrets, ",")
	if !strings.Contains(joined, "keep-secret-value") || !strings.Contains(joined, "gone-secret-value") {
		t.Fatalf("deleted account secret missing from redaction material: %#v", secrets)
	}
}

func TestMetadataSMTPHostIsRejected(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{
		AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging",
		ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai",
		Accounts:      []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}},
		Notifications: domain.NotificationConfig{Email: domain.EmailConfig{Host: "100.100.100.200"}},
	}
	if err = st.Setup(ctx, config); err == nil {
		t.Fatal("expected metadata SMTP host to be rejected")
	}
	config.Notifications.Email.Host = "smtp.example.test"
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataWebhookURLIsRejected(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{
		AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging",
		ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai",
		Accounts:      []domain.Account{{AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china"}},
		Notifications: domain.NotificationConfig{Webhook: domain.WebhookConfig{URL: "http://100.100.100.200/latest/meta-data/"}},
	}
	if err = st.Setup(ctx, config); err == nil {
		t.Fatal("expected metadata webhook URL to be rejected")
	}
	config.Notifications.Webhook.URL = "https://example.test/hook"
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	config.AdminPassword = ""
	config.Accounts[0].AccessKeySecret = ""
	config.Notifications.Webhook.URL = "file:///etc/passwd"
	if err = st.SaveConfig(ctx, config); err == nil {
		t.Fatal("expected file webhook URL to be rejected")
	}
}

func TestInvalidTimezoneIsRejected(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Not/AZone"}
	if err = st.Setup(ctx, config); err == nil {
		t.Fatal("expected invalid timezone to be rejected")
	}
	config.Timezone = "UTC"
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
}

func TestSetupRejectsOversizedTimezone(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: strings.Repeat("A", 65)}
	if err = st.Setup(context.Background(), config); err == nil || !strings.Contains(err.Error(), "invalid timezone") {
		t.Fatalf("oversized timezone err=%v", err)
	}
}

func TestAPIIntervalMinimum(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 29, Timezone: "Asia/Shanghai"}
	if err = st.Setup(ctx, config); err == nil {
		t.Fatal("expected API interval below 30 seconds to be rejected")
	}

	config.APIInterval = 30
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value='1' WHERE key='api_interval'`); err != nil {
		t.Fatal(err)
	}
	loaded, err := st.GetConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.APIInterval != minAPIIntervalSeconds {
		t.Fatalf("expected legacy interval to normalize to %d seconds, got %d", minAPIIntervalSeconds, loaded.APIInterval)
	}
}

func TestAPIKeyScopesAndRevocation(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	key, token, err := st.CreateAPIKey(ctx, "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := st.ValidateAPIKey(ctx, token)
	if err != nil || len(scopes) != 1 || scopes[0] != "widget:read" {
		t.Fatalf("scopes=%v err=%v", scopes, err)
	}
	if err = st.RevokeAPIKey(ctx, key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = st.ValidateAPIKey(ctx, token); err == nil {
		t.Fatal("revoked key must fail")
	}
	keys, err := st.ListAPIKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("revoked key should not be listed as active: %#v", keys)
	}
}

func TestListAPIKeysReturnsEmptyArrayWhenNoneExist(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	keys, err := st.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if keys == nil || len(keys) != 0 {
		t.Fatalf("expected a non-nil empty API key list, got %#v", keys)
	}
}

func TestListLogsReturnsEmptyArrayAfterClear(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	if err = st.AddLog(ctx, "audit", "test log"); err != nil {
		t.Fatal(err)
	}
	if err = st.ClearLogs(ctx, "action"); err != nil {
		t.Fatal(err)
	}
	entries, err := st.ListLogs(ctx, "action", 100)
	if err != nil {
		t.Fatal(err)
	}
	if entries == nil || len(entries) != 0 {
		t.Fatalf("expected a non-nil empty log list, got %#v", entries)
	}
}

func TestAddLogRejectsUnknownType(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.AddLog(context.Background(), "debug", "should not store"); err == nil || !strings.Contains(err.Error(), "log type is invalid") {
		t.Fatalf("unknown type err=%v", err)
	}
	entries, err := st.ListLogs(context.Background(), "action", 10)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unknown type stored logs=%#v err=%v", entries, err)
	}
}

func TestAddLogMessageIsClipped(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err = st.AddLog(ctx, "error", strings.Repeat("x", maxLogRunes+128)); err != nil {
		t.Fatal(err)
	}
	entries, err := st.ListLogs(ctx, "action", 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("logs=%#v err=%v", entries, err)
	}
	if got := []rune(entries[0].Message); len(got) != maxLogRunes || string(got) != strings.Repeat("x", maxLogRunes) {
		t.Fatalf("stored log len = %d", len(got))
	}
}

func TestAcquireLeaseRejectsOversizedIdentity(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.AcquireLease(ctx, "", "owner-a", time.Minute); err == nil || !strings.Contains(err.Error(), "lease identity is invalid") {
		t.Fatalf("empty name err=%v", err)
	}
	if _, err = st.AcquireLease(ctx, "monitor", "", time.Minute); err == nil || !strings.Contains(err.Error(), "lease identity is invalid") {
		t.Fatalf("empty owner err=%v", err)
	}
	if _, err = st.AcquireLease(ctx, strings.Repeat("n", maxLeaseNameRunes+1), "owner-a", time.Minute); err == nil || !strings.Contains(err.Error(), "lease identity is invalid") {
		t.Fatalf("name err=%v", err)
	}
	if _, err = st.AcquireLease(ctx, "monitor", strings.Repeat("o", maxLeaseOwnerRunes+1), time.Minute); err == nil || !strings.Contains(err.Error(), "lease identity is invalid") {
		t.Fatalf("owner err=%v", err)
	}
	got, err := st.AcquireLease(ctx, strings.Repeat("n", maxLeaseNameRunes), strings.Repeat("o", maxLeaseOwnerRunes), time.Minute)
	if err != nil || !got {
		t.Fatalf("max identity = %v err=%v", got, err)
	}
}

func TestAcquireLeaseRenewalExpiryAndOwnership(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	got, err := st.AcquireLease(ctx, "monitor", "owner-a", time.Minute)
	if err != nil || !got {
		t.Fatalf("first acquire = %v err=%v", got, err)
	}
	got, err = st.AcquireLease(ctx, "monitor", "owner-a", time.Minute)
	if err != nil || !got {
		t.Fatalf("same-owner refresh = %v err=%v", got, err)
	}
	got, err = st.AcquireLease(ctx, "monitor", "owner-b", time.Minute)
	if err != nil || got {
		t.Fatalf("other owner must wait for expiry, got %v err=%v", got, err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE scheduler_leases SET expires_at=unixepoch()-1 WHERE name='monitor'`); err != nil {
		t.Fatal(err)
	}
	got, err = st.AcquireLease(ctx, "monitor", "owner-b", time.Minute)
	if err != nil || !got {
		t.Fatalf("expired lease should be takeable, got %v err=%v", got, err)
	}
	got, err = st.AcquireLease(ctx, "monitor", "owner-a", time.Minute)
	if err != nil || got {
		t.Fatalf("previous owner must not steal a live lease, got %v err=%v", got, err)
	}
}

func TestRecordActionEventRejectsInvalidFields(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.RecordActionEvent(ctx, "", 1, "threshold", "detected", ""); err == nil || !strings.Contains(err.Error(), "key is invalid") {
		t.Fatalf("empty key err=%v", err)
	}
	if _, err = st.RecordActionEvent(ctx, strings.Repeat("k", maxActionEventKeyRunes+1), 1, "threshold", "detected", ""); err == nil || !strings.Contains(err.Error(), "key is invalid") {
		t.Fatalf("long key err=%v", err)
	}
	if _, err = st.RecordActionEvent(ctx, "threshold:1:active", 1, "unknown", "detected", ""); err == nil || !strings.Contains(err.Error(), "type is invalid") {
		t.Fatalf("type err=%v", err)
	}
	if _, err = st.RecordActionEvent(ctx, "threshold:1:active", 1, "threshold", "nope", ""); err == nil || !strings.Contains(err.Error(), "type is invalid") {
		t.Fatalf("status err=%v", err)
	}
	fresh, err := st.RecordActionEvent(ctx, "threshold:1:active", 1, "threshold", "detected", strings.Repeat("d", maxActionEventDetailRunes+8))
	if err != nil || !fresh {
		t.Fatalf("clipped detail = %v err=%v", fresh, err)
	}
	var detail string
	if err = st.db.QueryRow(`SELECT detail FROM action_events WHERE event_key='threshold:1:active'`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if got := []rune(detail); len(got) != maxActionEventDetailRunes {
		t.Fatalf("stored detail len = %d", len(got))
	}
}

func TestActionEventCanBeReleasedAfterFailure(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	fresh, err := st.RecordActionEvent(ctx, "schedule:1:day:start", 1, "schedule_start", "attempting", "")
	if err != nil || !fresh {
		t.Fatal(err)
	}
	fresh, _ = st.RecordActionEvent(ctx, "schedule:1:day:start", 1, "schedule_start", "attempting", "")
	if fresh {
		t.Fatal("duplicate event must be rejected")
	}
	if err = st.DeleteActionEvent(ctx, "schedule:1:day:start"); err != nil {
		t.Fatal(err)
	}
	fresh, err = st.RecordActionEvent(ctx, "schedule:1:day:start", 1, "schedule_start", "attempting", "")
	if err != nil || !fresh {
		t.Fatal("released event should be retryable")
	}
}

func TestFailedJobRetriesThenReleasesUniqueKey(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	job, err := st.EnqueueJob(ctx, "refresh_account", 1, `{}`, "refresh:1:retry", 2)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := st.ClaimJob(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.FailJob(ctx, claimed, errors.New("aliyun unavailable")); err != nil {
		t.Fatal(err)
	}
	var unique, status string
	if err = st.db.QueryRow(`SELECT unique_key,status FROM jobs WHERE id=?`, claimed.ID).Scan(&unique, &status); err != nil {
		t.Fatal(err)
	}
	if unique != "refresh:1:retry" || status != "queued" {
		t.Fatalf("retrying job unique_key=%q status=%q", unique, status)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE jobs SET available_at=unixepoch()-1 WHERE id=?`, claimed.ID); err != nil {
		t.Fatal(err)
	}
	claimed, err = st.ClaimJob(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.FailJob(ctx, claimed, errors.New("aliyun unavailable")); err != nil {
		t.Fatal(err)
	}
	if err = st.db.QueryRow(`SELECT COALESCE(unique_key,''),status FROM jobs WHERE id=?`, claimed.ID).Scan(&unique, &status); err != nil {
		t.Fatal(err)
	}
	if unique != "" || status != "failed" {
		t.Fatalf("exhausted job unique_key=%q status=%q", unique, status)
	}
	replacement, err := st.EnqueueJob(ctx, "refresh_account", 1, `{}`, "refresh:1:retry", 2)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.ID == job.ID {
		t.Fatal("released unique_key should allow a new job")
	}
}

func TestEnqueueJobRejectsInvalidTypeAndAttempts(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.EnqueueJob(ctx, "", 1, `{}`, "", 3); err == nil || !strings.Contains(err.Error(), "job type is invalid") {
		t.Fatalf("empty type err=%v", err)
	}
	if _, err = st.EnqueueJob(ctx, strings.Repeat("t", maxJobTypeRunes+1), 1, `{}`, "", 3); err == nil || !strings.Contains(err.Error(), "job type is invalid") {
		t.Fatalf("long type err=%v", err)
	}
	if _, err = st.EnqueueJob(ctx, "refresh_account", 1, `{}`, "", 0); err == nil || !strings.Contains(err.Error(), "attempts are invalid") {
		t.Fatalf("zero attempts err=%v", err)
	}
	if _, err = st.EnqueueJob(ctx, "refresh_account", 1, `{}`, "", maxJobAttempts+1); err == nil || !strings.Contains(err.Error(), "attempts are invalid") {
		t.Fatalf("max attempts err=%v", err)
	}
	if _, err = st.EnqueueJob(ctx, strings.Repeat("t", maxJobTypeRunes), 1, `{}`, "", maxJobAttempts); err != nil {
		t.Fatalf("max job type err=%v", err)
	}
}

func TestEnqueueJobRejectsOversizedPayloadAndUniqueKey(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.EnqueueJob(ctx, "refresh_account", 1, strings.Repeat("x", maxJobPayloadRunes+1), "", 3); err == nil || !strings.Contains(err.Error(), "payload is too long") {
		t.Fatalf("payload err=%v", err)
	}
	if _, err = st.EnqueueJob(ctx, "refresh_account", 1, `{}`, strings.Repeat("k", maxJobUniqueKeyRunes+1), 3); err == nil || !strings.Contains(err.Error(), "unique key is too long") {
		t.Fatalf("unique key err=%v", err)
	}
	if _, err = st.EnqueueJob(ctx, "refresh_account", 1, strings.Repeat("x", maxJobPayloadRunes), strings.Repeat("k", maxJobUniqueKeyRunes), 3); err != nil {
		t.Fatalf("max job fields err=%v", err)
	}
}

func TestMonitorJobKeepsMinuteDeduplicationAfterCompletion(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	job, err := st.EnqueueJob(ctx, "monitor_account", 1, `{}`, "monitor:1:202607191200", 3)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.CompleteJob(ctx, job.ID, "ok"); err != nil {
		t.Fatal(err)
	}
	duplicate, err := st.EnqueueJob(ctx, "monitor_account", 1, `{}`, "monitor:1:202607191200", 3)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate.ID != job.ID {
		t.Fatalf("duplicate created new job %s instead of %s", duplicate.ID, job.ID)
	}
}

func TestCreateExclusiveSessionReplacesPrevious(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	first, err := st.CreateSession(ctx, "127.0.0.1", "first", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.CreateExclusiveSession(ctx, "127.0.0.2", "second", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if valid, _ := st.ValidateSession(ctx, first); valid {
		t.Fatal("previous session must be replaced")
	}
	if valid, _ := st.ValidateSession(ctx, second); !valid {
		t.Fatal("exclusive session must validate")
	}
	var count int
	if err = st.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("session count = %d err=%v", count, err)
	}
}

func TestSessionUserAgentIsClipped(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	long := strings.Repeat("A", 1024) + "💣"
	token, err := st.CreateExclusiveSession(ctx, "127.0.0.1", long, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if valid, _ := st.ValidateSession(ctx, token); !valid {
		t.Fatal("clipped session must validate")
	}
	var stored string
	if err = st.db.QueryRow(`SELECT user_agent FROM sessions`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != strings.Repeat("A", maxUserAgentRunes) {
		t.Fatalf("stored user agent len = %d value = %q", len([]rune(stored)), stored)
	}
}

func TestLoginFailureIPIsClipped(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	long := strings.Repeat("9", 128)
	if err = st.RecordLoginFailure(ctx, long); err != nil {
		t.Fatal(err)
	}
	count, err := st.RecentLoginFailures(ctx, long, time.Now().Add(-time.Minute))
	if err != nil || count != 1 {
		t.Fatalf("recent failures = %d err=%v", count, err)
	}
	var stored string
	if err = st.db.QueryRow(`SELECT ip FROM login_attempts`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != strings.Repeat("9", maxIPRunes) {
		t.Fatalf("stored ip = %q", stored)
	}
	if err = st.ClearLoginFailures(ctx, long); err != nil {
		t.Fatal(err)
	}
	count, err = st.RecentLoginFailures(ctx, long, time.Now().Add(-time.Minute))
	if err != nil || count != 0 {
		t.Fatalf("cleared failures = %d err=%v", count, err)
	}
}

func TestSessionExpiry(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	token, err := st.CreateSession(context.Background(), "127.0.0.1", "test", -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := st.ValidateSession(context.Background(), token)
	if err != nil || valid {
		t.Fatal("expired session must not validate")
	}
}

func TestUpdateAdminPasswordKeepsCurrentSessionOnly(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err = st.Setup(ctx, domain.Config{AdminPassword: "Original-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai"}); err != nil {
		t.Fatal(err)
	}
	current, err := st.CreateSession(ctx, "127.0.0.1", "current", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other, err := st.CreateSession(ctx, "127.0.0.2", "other", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.UpdateAdminPassword(ctx, "Replacement-Password-84!", current); err != nil {
		t.Fatal(err)
	}
	if valid, _ := st.VerifyAdminPassword(ctx, "Original-Password-42!"); valid {
		t.Fatal("old password must no longer validate")
	}
	if valid, _ := st.VerifyAdminPassword(ctx, "Replacement-Password-84!"); !valid {
		t.Fatal("new password must validate")
	}
	if valid, _ := st.ValidateSession(ctx, current); !valid {
		t.Fatal("current session must remain valid")
	}
	if valid, _ := st.ValidateSession(ctx, other); valid {
		t.Fatal("other sessions must be invalidated")
	}
}

func TestPruneDeletesOldCompletedJobs(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,status,available_at,created_at,updated_at) VALUES('old','refresh_account','completed',unixepoch()-700000,unixepoch()-700000,unixepoch()-700000),('fresh','refresh_account','completed',unixepoch(),unixepoch(),unixepoch()),('queued','refresh_account','queued',unixepoch()-700000,unixepoch()-700000,unixepoch()-700000)`); err != nil {
		t.Fatal(err)
	}
	if err = st.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	var oldCount, freshCount, queuedCount int
	if err = st.db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE id='old'`).Scan(&oldCount); err != nil || oldCount != 0 {
		t.Fatalf("old job count = %d err=%v", oldCount, err)
	}
	if err = st.db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE id='fresh'`).Scan(&freshCount); err != nil || freshCount != 1 {
		t.Fatalf("fresh job count = %d err=%v", freshCount, err)
	}
	if err = st.db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE id='queued'`).Scan(&queuedCount); err != nil || queuedCount != 1 {
		t.Fatalf("queued job count = %d err=%v", queuedCount, err)
	}
}

func TestPruneDeletesOldHeartbeatLogs(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO logs(type,message,created_at) VALUES('heartbeat','old',unixepoch()-259201),('heartbeat','new',unixepoch()),('audit','keep',unixepoch()-259201)`); err != nil {
		t.Fatal(err)
	}
	if err = st.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	var heartbeat, audit int
	if err = st.db.QueryRow(`SELECT COUNT(*) FROM logs WHERE type='heartbeat'`).Scan(&heartbeat); err != nil || heartbeat != 1 {
		t.Fatalf("heartbeat count = %d err=%v", heartbeat, err)
	}
	if err = st.db.QueryRow(`SELECT COUNT(*) FROM logs WHERE type='audit'`).Scan(&audit); err != nil || audit != 1 {
		t.Fatalf("audit count = %d err=%v", audit, err)
	}
}

func TestPruneDeletesOldLoginAttempts(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO login_attempts(ip,attempt_time) VALUES('1.1.1.1',unixepoch()-90000),('1.1.1.1',unixepoch())`); err != nil {
		t.Fatal(err)
	}
	if err = st.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = st.db.QueryRow(`SELECT COUNT(*) FROM login_attempts`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("login_attempts count = %d err=%v", count, err)
	}
}

func TestPruneDeletesExpiredSessionsOnly(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	expired, err := st.CreateSession(ctx, "127.0.0.1", "expired", -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	live, err := st.CreateSession(ctx, "127.0.0.1", "live", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	if valid, _ := st.ValidateSession(ctx, expired); valid {
		t.Fatal("expired session should be pruned")
	}
	if valid, _ := st.ValidateSession(ctx, live); !valid {
		t.Fatal("live session must survive prune")
	}
	var count int
	if err = st.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("session count = %d err=%v", count, err)
	}
}

func TestPruneDeletesOldTrafficAndBillingCache(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `
INSERT INTO traffic_hourly(account_id,traffic,recorded_at) VALUES(1,1.5,unixepoch()-172801),(1,2.5,unixepoch());
INSERT INTO traffic_daily(account_id,traffic,recorded_at) VALUES(1,10,unixepoch()-5184001),(1,20,unixepoch());
INSERT INTO billing_cache(account_id,cache_type,billing_cycle,data,updated_at) VALUES(1,'balance','','{}',unixepoch()-7776001),(1,'bill','2026-09','{}',unixepoch());
`); err != nil {
		t.Fatal(err)
	}
	if err = st.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	var hourly, daily, billing int
	if err = st.db.QueryRow(`SELECT COUNT(*) FROM traffic_hourly`).Scan(&hourly); err != nil || hourly != 1 {
		t.Fatalf("hourly count = %d err=%v", hourly, err)
	}
	if err = st.db.QueryRow(`SELECT COUNT(*) FROM traffic_daily`).Scan(&daily); err != nil || daily != 1 {
		t.Fatalf("daily count = %d err=%v", daily, err)
	}
	if err = st.db.QueryRow(`SELECT COUNT(*) FROM billing_cache`).Scan(&billing); err != nil || billing != 1 {
		t.Fatalf("billing count = %d err=%v", billing, err)
	}
	var hourlyTraffic, dailyTraffic float64
	if err = st.db.QueryRow(`SELECT traffic FROM traffic_hourly`).Scan(&hourlyTraffic); err != nil || hourlyTraffic != 2.5 {
		t.Fatalf("kept hourly traffic = %v err=%v", hourlyTraffic, err)
	}
	if err = st.db.QueryRow(`SELECT traffic FROM traffic_daily`).Scan(&dailyTraffic); err != nil || dailyTraffic != 20 {
		t.Fatalf("kept daily traffic = %v err=%v", dailyTraffic, err)
	}
}

func TestBillingCacheRejectsInvalidKeysAndOversizedPayload(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err = st.SetBillingCache(ctx, 1, "unknown", "", map[string]float64{"amount": 1}); err == nil || !strings.Contains(err.Error(), "key is invalid") {
		t.Fatalf("type err=%v", err)
	}
	if err = st.SetBillingCache(ctx, 1, "instance_bill", "202609", map[string]float64{"amount": 1}); err == nil || !strings.Contains(err.Error(), "key is invalid") {
		t.Fatalf("cycle err=%v", err)
	}
	if _, err = st.BillingCache(ctx, 1, "nope", "", time.Hour, &map[string]any{}); err == nil || !strings.Contains(err.Error(), "key is invalid") {
		t.Fatalf("get type err=%v", err)
	}
	if err = st.SetBillingCache(ctx, 1, "error", "", map[string]string{"message": strings.Repeat("m", maxBillingCacheBytes)}); err == nil || !strings.Contains(err.Error(), "payload is too long") {
		t.Fatalf("payload err=%v", err)
	}
	if err = st.SetBillingCache(ctx, 1, "instance_bill", "2026-09", map[string]float64{"total": 1}); err != nil {
		t.Fatal(err)
	}
}

func TestBillingCacheIsIsolatedPerAccount(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err = st.SetBillingCache(ctx, 1, "balance", "", map[string]float64{"amount": 10.5}); err != nil {
		t.Fatal(err)
	}
	var got map[string]float64
	ok, err := st.BillingCache(ctx, 2, "balance", "", time.Hour, &got)
	if err != nil || ok {
		t.Fatalf("account 2 must miss, ok=%v err=%v", ok, err)
	}
	ok, err = st.BillingCache(ctx, 1, "balance", "", time.Hour, &got)
	if err != nil || !ok || got["amount"] != 10.5 {
		t.Fatalf("account 1 cache=%v ok=%v err=%v", got, ok, err)
	}
}

func TestBillingCacheExpiresByMaxAge(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err = st.SetBillingCache(ctx, 1, "balance", "", map[string]float64{"amount": 8}); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE billing_cache SET updated_at=unixepoch()-120`); err != nil {
		t.Fatal(err)
	}
	var got map[string]float64
	ok, err := st.BillingCache(ctx, 1, "balance", "", 30*time.Second, &got)
	if err != nil || ok {
		t.Fatalf("stale cache must miss, ok=%v err=%v", ok, err)
	}
}

func TestPruneDeletesSentAndFailedOutbox(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `
INSERT INTO notification_outbox(id,event_id,channel,payload,status,attempts,max_attempts,available_at,last_error,created_at,updated_at) VALUES
('old-sent','evt-old-sent','telegram','{}','sent',1,5,unixepoch()-2592001,'',unixepoch()-2592001,unixepoch()-2592001),
('fresh-sent','evt-fresh-sent','telegram','{}','sent',1,5,unixepoch(),'',unixepoch(),unixepoch()),
('old-failed','evt-old-failed','webhook','{}','failed',5,5,unixepoch()-2592001,'boom',unixepoch()-2592001,unixepoch()-2592001),
('fresh-failed','evt-fresh-failed','webhook','{}','failed',5,5,unixepoch(),'boom',unixepoch(),unixepoch()),
('old-queued','evt-old-queued','email','{}','queued',0,5,unixepoch()-2592001,'',unixepoch()-2592001,unixepoch()-2592001)
`); err != nil {
		t.Fatal(err)
	}
	if err = st.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	var ids string
	if err = st.db.QueryRow(`SELECT GROUP_CONCAT(id, ',') FROM (SELECT id FROM notification_outbox ORDER BY id)`).Scan(&ids); err != nil {
		t.Fatal(err)
	}
	if ids != "fresh-failed,fresh-sent,old-queued" {
		t.Fatalf("kept outbox ids = %q", ids)
	}
}

func TestSessionStoresHashNotPlaintext(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	token, err := st.CreateSession(context.Background(), "127.0.0.1", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err = st.db.QueryRow(`SELECT token_hash FROM sessions`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "" || stored == token {
		t.Fatal("session token was stored in plaintext")
	}
	if stored != security.TokenHash(token) {
		t.Fatalf("stored hash = %q", stored)
	}
	valid, err := st.ValidateSession(context.Background(), token)
	if err != nil || !valid {
		t.Fatal("hashed session must still validate")
	}
	valid, err = st.ValidateSession(context.Background(), "not-the-token")
	if err != nil || valid {
		t.Fatal("unknown session token must not validate")
	}
}

func TestExpiredAPIKeyIsRejected(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	token := "cdt_expired_test_token"
	_, err = st.db.Exec(`INSERT INTO api_keys(name,token_hash,scopes,created_at,expires_at) VALUES('expired',?,'["widget:read"]',unixepoch(),unixepoch()-30)`, security.TokenHash(token))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.ValidateAPIKey(context.Background(), token); err == nil {
		t.Fatal("expired API key must not validate")
	}
}

func TestCreateAPIKeyRejectsWhenAtCap(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	for i := 0; i < maxAPIKeys; i++ {
		if _, _, err = st.CreateAPIKey(ctx, "key-"+strconv.Itoa(i), []string{"widget:read"}, nil); err != nil {
			t.Fatalf("create %d err=%v", i, err)
		}
	}
	if _, _, err = st.CreateAPIKey(ctx, "overflow", []string{"widget:read"}, nil); err == nil || !strings.Contains(err.Error(), "too many api keys") {
		t.Fatalf("cap err=%v", err)
	}
	keys, err := st.ListAPIKeys(ctx)
	if err != nil || len(keys) != maxAPIKeys {
		t.Fatalf("listed %d err=%v", len(keys), err)
	}
	if err = st.RevokeAPIKey(ctx, keys[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = st.CreateAPIKey(ctx, "replacement", []string{"widget:read"}, nil); err != nil {
		t.Fatalf("after revoke err=%v", err)
	}
}

func TestCreateAPIKeyRejectsEmptyNameAndScopes(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, _, err = st.CreateAPIKey(ctx, "  ", []string{"widget:read"}, nil); err == nil {
		t.Fatal("expected blank name to be rejected")
	}
	if _, _, err = st.CreateAPIKey(ctx, "widget", nil, nil); err == nil {
		t.Fatal("expected empty scopes to be rejected")
	}
	if _, _, err = st.CreateAPIKey(ctx, "widget", []string{}, nil); err == nil {
		t.Fatal("expected empty scope list to be rejected")
	}
}

func TestCreateAPIKeyRejectsOversizedName(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, _, err = st.CreateAPIKey(ctx, strings.Repeat("n", maxAPIKeyNameRunes+1), []string{"widget:read"}, nil); err == nil {
		t.Fatal("expected oversized name to be rejected")
	}
	key, _, err := st.CreateAPIKey(ctx, strings.Repeat("n", maxAPIKeyNameRunes), []string{"widget:read"}, nil)
	if err != nil || key.Name != strings.Repeat("n", maxAPIKeyNameRunes) {
		t.Fatalf("max-length name key=%#v err=%v", key, err)
	}
}

func TestCreateAPIKeyRejectsOversizedScopeList(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	scopes := make([]string, maxAPIKeyScopes+1)
	for i := range scopes {
		scopes[i] = "widget:read"
	}
	if _, _, err = st.CreateAPIKey(context.Background(), "widget", scopes, nil); err == nil || !strings.Contains(err.Error(), "invalid API key scope") {
		t.Fatalf("scope list err=%v", err)
	}
	keys, err := st.ListAPIKeys(context.Background())
	if err != nil || len(keys) != 0 {
		t.Fatalf("listed %d err=%v", len(keys), err)
	}
}

func TestCreateAPIKeyRejectsUnknownScopes(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, _, err = st.CreateAPIKey(ctx, "admin", []string{"admin"}, nil); err == nil {
		t.Fatal("expected admin scope to be rejected")
	}
	if _, _, err = st.CreateAPIKey(ctx, "mixed", []string{"widget:read", "admin"}, nil); err == nil {
		t.Fatal("expected mixed unknown scope to be rejected")
	}
	if _, _, err = st.CreateAPIKey(ctx, "widget", []string{"widget:read"}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCreateAPIKeyDeduplicatesScopes(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key, token, err := st.CreateAPIKey(context.Background(), "widget", []string{"widget:read", "instance:control", "widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(key.Scopes) != 2 || key.Scopes[0] != "widget:read" || key.Scopes[1] != "instance:control" {
		t.Fatalf("scopes=%v", key.Scopes)
	}
	got, err := st.ValidateAPIKey(context.Background(), token)
	if err != nil || len(got) != 2 || got[0] != "widget:read" || got[1] != "instance:control" {
		t.Fatalf("validated scopes=%v err=%v", got, err)
	}
}

func TestValidateAPIKeyIgnoresUnknownScopes(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	adminToken := "cdt_legacy_admin_scope"
	mixedToken := "cdt_legacy_mixed_scope"
	if _, err = st.db.Exec(`INSERT INTO api_keys(name,token_hash,scopes,created_at) VALUES('admin',?,'["admin"]',unixepoch()),('mixed',?,'["widget:read","admin"]',unixepoch())`, security.TokenHash(adminToken), security.TokenHash(mixedToken)); err != nil {
		t.Fatal(err)
	}
	if _, err = st.ValidateAPIKey(ctx, adminToken); err == nil {
		t.Fatal("admin-only key must not validate")
	}
	scopes, err := st.ValidateAPIKey(ctx, mixedToken)
	if err != nil || len(scopes) != 1 || scopes[0] != "widget:read" {
		t.Fatalf("mixed scopes=%v err=%v", scopes, err)
	}
	var adminUsed, mixedUsed sql.NullInt64
	if err = st.db.QueryRow(`SELECT last_used_at FROM api_keys WHERE name='admin'`).Scan(&adminUsed); err != nil {
		t.Fatal(err)
	}
	if err = st.db.QueryRow(`SELECT last_used_at FROM api_keys WHERE name='mixed'`).Scan(&mixedUsed); err != nil {
		t.Fatal(err)
	}
	if adminUsed.Valid {
		t.Fatal("rejected admin key must not record last_used_at")
	}
	if !mixedUsed.Valid {
		t.Fatal("usable mixed key should record last_used_at")
	}
}

func TestCreateAPIKeyRejectsPastExpiry(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	past := time.Now().Add(-time.Minute)
	if _, _, err = st.CreateAPIKey(context.Background(), "old", []string{"widget:read"}, &past); err == nil {
		t.Fatal("expected past expiry to be rejected")
	}
	future := time.Now().Add(time.Hour)
	_, token, err := st.CreateAPIKey(context.Background(), "fresh", []string{"widget:read"}, &future)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.ValidateAPIKey(context.Background(), token); err != nil {
		t.Fatalf("future expiry must validate: %v", err)
	}
}

func TestAPIKeyHashIsStoredNotToken(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, token, err := st.CreateAPIKey(context.Background(), "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err = st.db.QueryRow(`SELECT token_hash FROM api_keys`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "" || stored == token || stored == token[len("cdt_"):] {
		t.Fatal("API key token was stored in plaintext")
	}
}

func TestAPIKeyLastUsedIsUpdatedOnValidate(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	key, token, err := st.CreateAPIKey(ctx, "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := st.ListAPIKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].LastUsedAt != nil {
		t.Fatalf("unused key last_used=%#v err=%v", keys, err)
	}
	if _, err = st.ValidateAPIKey(ctx, token); err != nil {
		t.Fatal(err)
	}
	keys, err = st.ListAPIKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].LastUsedAt == nil {
		t.Fatalf("used key last_used=%#v err=%v", keys, err)
	}
	var stored int64
	if err = st.db.QueryRow(`SELECT last_used_at FROM api_keys WHERE id=?`, key.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored < 1 {
		t.Fatal("last_used_at was not persisted")
	}
}

func TestCorruptAPIKeyScopesDoNotRecordLastUsed(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	token := "cdt_corrupt_scopes_token"
	if _, err = st.db.Exec(`INSERT INTO api_keys(name,token_hash,scopes,created_at) VALUES('broken',?,'not-json',unixepoch())`, security.TokenHash(token)); err != nil {
		t.Fatal(err)
	}
	if _, err = st.ValidateAPIKey(context.Background(), token); err == nil {
		t.Fatal("expected corrupt scopes to fail")
	}
	var lastUsed sql.NullInt64
	if err = st.db.QueryRow(`SELECT last_used_at FROM api_keys`).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if lastUsed.Valid {
		t.Fatal("corrupt key must not record last_used_at")
	}
}

func TestSavePasskeyRejectsWhenAtCap(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	for i := 0; i < maxPasskeys; i++ {
		credential := webauthn.Credential{ID: []byte("credential-" + strconv.Itoa(i)), PublicKey: []byte("public-key")}
		if err = st.SavePasskey(ctx, "key-"+strconv.Itoa(i), credential); err != nil {
			t.Fatalf("create %d err=%v", i, err)
		}
	}
	if err = st.SavePasskey(ctx, "overflow", webauthn.Credential{ID: []byte("overflow"), PublicKey: []byte("public-key")}); err == nil || !strings.Contains(err.Error(), "too many passkeys") {
		t.Fatalf("cap err=%v", err)
	}
	items, err := st.ListPasskeys(ctx)
	if err != nil || len(items) != maxPasskeys {
		t.Fatalf("listed %d err=%v", len(items), err)
	}
}

func TestSavePasskeyRejectsOversizedCredential(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err = st.SavePasskey(ctx, "empty", webauthn.Credential{}); err == nil || !strings.Contains(err.Error(), "credential is invalid") {
		t.Fatalf("empty err=%v", err)
	}
	huge := webauthn.Credential{ID: []byte("credential-id"), PublicKey: []byte(strings.Repeat("k", maxPasskeyJSONBytes))}
	if err = st.SavePasskey(ctx, "huge", huge); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("json err=%v", err)
	}
	items, err := st.ListPasskeys(ctx)
	if err != nil || len(items) != 0 {
		t.Fatalf("rejected passkeys=%#v err=%v", items, err)
	}
}

func TestSavePasskeyRejectsOversizedName(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	credential := webauthn.Credential{ID: []byte("credential-id"), PublicKey: []byte("public-key")}
	if err = st.SavePasskey(ctx, strings.Repeat("n", maxPasskeyNameRunes+1), credential); err == nil {
		t.Fatal("expected oversized passkey name to be rejected")
	}
	if err = st.SavePasskey(ctx, strings.Repeat("n", maxPasskeyNameRunes), credential); err != nil {
		t.Fatal(err)
	}
	items, err := st.ListPasskeys(ctx)
	if err != nil || len(items) != 1 || items[0].Name != strings.Repeat("n", maxPasskeyNameRunes) {
		t.Fatalf("passkeys=%#v err=%v", items, err)
	}
}

func TestPasskeyCredentialRoundTrip(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	credential := webauthn.Credential{ID: []byte("credential-id"), PublicKey: []byte("public-key")}
	if err = st.SavePasskey(ctx, "workstation", credential); err != nil {
		t.Fatal(err)
	}
	credentials, err := st.LoadPasskeyCredentials(ctx)
	if err != nil || len(credentials) != 1 || string(credentials[0].ID) != "credential-id" {
		t.Fatalf("credentials=%#v err=%v", credentials, err)
	}
	items, err := st.ListPasskeys(ctx)
	if err != nil || len(items) != 1 || items[0].Name != "workstation" {
		t.Fatalf("passkeys=%#v err=%v", items, err)
	}
	if err = st.UpdatePasskeyCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	items, err = st.ListPasskeys(ctx)
	if err != nil || items[0].LastUsedAt == nil {
		t.Fatal("passkey last-used timestamp was not updated")
	}
	if err = st.DeletePasskey(ctx, items[0].ID); err != nil {
		t.Fatal(err)
	}
	items, err = st.ListPasskeys(ctx)
	if err != nil || items == nil || len(items) != 0 {
		t.Fatalf("expected non-nil empty passkey list, got %#v", items)
	}
}

func TestInterruptedWorkRecoversOnOpen(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.db.Exec(`INSERT INTO jobs(id,type,status,available_at,locked_at,created_at,updated_at) VALUES('stale','monitor_account','running',unixepoch()-300,unixepoch()-300,unixepoch()-300,unixepoch()-300)`)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var status string
	if err = st.db.QueryRow(`SELECT status FROM jobs WHERE id='stale'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "queued" {
		t.Fatalf("status = %s", status)
	}
}

func TestSQLiteUsesWALAndBusyTimeout(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var mode string
	if err = st.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(mode, "wal") {
		t.Fatalf("journal_mode = %s", mode)
	}
	var timeout int
	if err = st.db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil {
		t.Fatal(err)
	}
	if timeout != 5000 {
		t.Fatalf("busy_timeout = %d", timeout)
	}
	var foreignKeys int
	if err = st.db.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d", foreignKeys)
	}
}

func TestSQLiteFilesAreOwnerReadableOnly(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("data dir mode = %v", info.Mode().Perm())
	}
	for _, name := range []string{"data.sqlite", "data.sqlite-wal", "data.sqlite-shm"} {
		path := filepath.Join(dir, name)
		info, err = os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v", name, info.Mode().Perm())
		}
	}
}

func TestTwoStoresCannotClaimTheSameJob(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	ctx := context.Background()
	if _, err = first.EnqueueJob(ctx, "monitor_account", 1, `{}`, "monitor:1:wal", 3); err != nil {
		t.Fatal(err)
	}
	claimed, err := first.ClaimJob(ctx)
	if err != nil || claimed.ID == "" {
		t.Fatalf("first claim = %#v err=%v", claimed, err)
	}
	_, err = second.ClaimJob(ctx)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second store must not claim the same job, err=%v", err)
	}
}

func TestAddOutboxRejectsInvalidChannelAndOversizedPayload(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	event := domain.NotificationEvent{ID: "evt-1", Type: "threshold", Title: "t", Summary: "s"}
	if err = st.AddOutbox(ctx, event, []string{"sms"}); err == nil || !strings.Contains(err.Error(), "channel is invalid") {
		t.Fatalf("channel err=%v", err)
	}
	if err = st.AddOutbox(ctx, domain.NotificationEvent{ID: "", Type: "threshold"}, []string{"email"}); err == nil || !strings.Contains(err.Error(), "event id is invalid") {
		t.Fatalf("empty id err=%v", err)
	}
	event.Summary = strings.Repeat("s", maxOutboxPayloadRunes)
	if err = st.AddOutbox(ctx, event, []string{"email"}); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("payload err=%v", err)
	}
	event.Summary = "s"
	event.Type = "unknown"
	if err = st.AddOutbox(ctx, event, []string{"email"}); err == nil || !strings.Contains(err.Error(), "event type is invalid") {
		t.Fatalf("type err=%v", err)
	}
	event.Type = "threshold"
	event.Title = strings.Repeat("t", maxNotificationTitleRunes+1)
	if err = st.AddOutbox(ctx, event, []string{"email"}); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("title err=%v", err)
	}
	event.Title = "t"
	event.Fields = map[string]string{strings.Repeat("k", maxNotificationFieldRunes+1): "v"}
	if err = st.AddOutbox(ctx, event, []string{"email"}); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("field err=%v", err)
	}
	event.Fields = map[string]string{}
	for i := 0; i < maxNotificationFields+1; i++ {
		event.Fields[strconv.Itoa(i)] = "v"
	}
	if err = st.AddOutbox(ctx, event, []string{"email"}); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("field count err=%v", err)
	}
	var count int
	if err = st.db.QueryRow(`SELECT COUNT(*) FROM notification_outbox`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected outbox count = %d err=%v", count, err)
	}
}

func TestOutboxInsertIsIdempotentAndClaimedOnce(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	event := domain.NotificationEvent{ID: "evt-1", Type: "threshold", Title: "t", Summary: "s"}
	if err = st.AddOutbox(ctx, event, []string{"telegram", "email"}); err != nil {
		t.Fatal(err)
	}
	if err = st.AddOutbox(ctx, event, []string{"telegram", "email"}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = st.db.QueryRow(`SELECT COUNT(*) FROM notification_outbox`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("outbox count = %d err=%v", count, err)
	}
	first, err := st.ClaimOutbox(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.ClaimOutbox(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatalf("claimed the same outbox row twice: %#v", first)
	}
	_, err = st.ClaimOutbox(ctx)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected no remaining outbox, err=%v", err)
	}
}

func TestAddTrafficStatsRejectsNonFiniteValues(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	for _, value := range []float64{-1, math.NaN(), math.Inf(1), maxAccountTrafficGB + 1} {
		if err = st.AddTrafficStats(ctx, 1, value, now); err == nil || !strings.Contains(err.Error(), "traffic sample is invalid") {
			t.Fatalf("traffic=%v err=%v", value, err)
		}
	}
	if err = st.AddTrafficStats(ctx, 1, 0, now); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRuntimeRejectsInvalidStatusAndTraffic(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	if err = st.UpdateRuntime(ctx, 1, math.NaN(), domain.StatusRunning, now); err == nil || !strings.Contains(err.Error(), "traffic sample is invalid") {
		t.Fatalf("nan traffic err=%v", err)
	}
	if err = st.UpdateRuntime(ctx, 1, 1, "exploded", now); err == nil || !strings.Contains(err.Error(), "instance status is invalid") {
		t.Fatalf("status err=%v", err)
	}
	if err = st.UpdateRuntime(ctx, 1, 1, domain.StatusRunning, now); err != nil {
		t.Fatal(err)
	}
	if err = st.UpdateRuntime(ctx, 1, 1, "Pending", now); err != nil {
		t.Fatal(err)
	}
}

func TestTrafficStatsUpsertAndHistoryOrder(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	empty, err := st.History(ctx, 1)
	if err != nil || empty.Hourly == nil || empty.Daily == nil || len(empty.Hourly) != 0 || len(empty.Daily) != 0 {
		t.Fatalf("empty history = %#v err=%v", empty, err)
	}
	now := time.Date(2026, 9, 8, 15, 30, 0, 0, time.UTC)
	if err = st.AddTrafficStats(ctx, 1, 10.5, now); err != nil {
		t.Fatal(err)
	}
	if err = st.AddTrafficStats(ctx, 1, 12.25, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = st.AddTrafficStats(ctx, 1, 20, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	history, err := st.History(ctx, 1)
	if err != nil || len(history.Hourly) != 2 || history.Hourly[0].Traffic != 12.25 || history.Hourly[1].Traffic != 20 {
		t.Fatalf("hourly history = %#v err=%v", history.Hourly, err)
	}
	if len(history.Daily) != 1 || history.Daily[0].Traffic != 20 {
		t.Fatalf("daily history should keep latest same-day value, got %#v", history.Daily)
	}
}

func TestTrafficHistoryIsIsolatedPerAccount(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 16, 0, 0, 0, time.UTC)
	if err = st.AddTrafficStats(ctx, 1, 11, now); err != nil {
		t.Fatal(err)
	}
	if err = st.AddTrafficStats(ctx, 2, 22, now); err != nil {
		t.Fatal(err)
	}
	one, err := st.History(ctx, 1)
	if err != nil || len(one.Hourly) != 1 || one.Hourly[0].Traffic != 11 {
		t.Fatalf("account 1 history = %#v err=%v", one.Hourly, err)
	}
	two, err := st.History(ctx, 2)
	if err != nil || len(two.Hourly) != 1 || two.Hourly[0].Traffic != 22 {
		t.Fatalf("account 2 history = %#v err=%v", two.Hourly, err)
	}
	missing, err := st.History(ctx, 3)
	if err != nil || missing.Hourly == nil || len(missing.Hourly) != 0 || missing.Daily == nil || len(missing.Daily) != 0 {
		t.Fatalf("missing account history = %#v err=%v", missing, err)
	}
}

func TestOutboxRetriesThenExhausts(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	_, err = st.db.Exec(`INSERT INTO notification_outbox(id,event_id,channel,payload,status,attempts,max_attempts,available_at,last_error,created_at,updated_at) VALUES('out-1','evt-1','telegram','{}','queued',0,2,unixepoch(),'',unixepoch(),unixepoch())`)
	if err != nil {
		t.Fatal(err)
	}
	item, err := st.ClaimOutbox(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.FailOutbox(ctx, item, errors.New("telegram unavailable")); err != nil {
		t.Fatal(err)
	}
	var status, lastError string
	if err = st.db.QueryRow(`SELECT status,last_error FROM notification_outbox WHERE id='out-1'`).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || lastError != "telegram unavailable" {
		t.Fatalf("retry status=%q last_error=%q", status, lastError)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE notification_outbox SET available_at=unixepoch()-1 WHERE id='out-1'`); err != nil {
		t.Fatal(err)
	}
	item, err = st.ClaimOutbox(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.FailOutbox(ctx, item, errors.New("telegram unavailable")); err != nil {
		t.Fatal(err)
	}
	if err = st.db.QueryRow(`SELECT status FROM notification_outbox WHERE id='out-1'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("exhausted status = %s", status)
	}
	if _, err = st.ClaimOutbox(ctx); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("exhausted outbox should not be claimed, err=%v", err)
	}
}

func TestInterruptedOutboxRecoversOnOpen(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.db.Exec(`INSERT INTO notification_outbox(id,event_id,channel,payload,status,attempts,max_attempts,available_at,last_error,created_at,updated_at) VALUES('stale-outbox','evt','telegram','{}','sending',1,5,unixepoch()-300,'',unixepoch()-300,unixepoch()-300)`)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var status string
	if err = st.db.QueryRow(`SELECT status FROM notification_outbox WHERE id='stale-outbox'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "queued" {
		t.Fatalf("status = %s", status)
	}
}

func TestLegacyTrafficTablesMigrateToStableAccountIDs(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", dir+"/data.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, access_key_id TEXT, access_key_secret TEXT, region_id TEXT, instance_id TEXT, max_traffic REAL, schedule_enabled INTEGER DEFAULT 0, start_time TEXT, stop_time TEXT, traffic_used REAL DEFAULT 0, instance_status TEXT DEFAULT 'Unknown', updated_at INTEGER DEFAULT 0, last_keep_alive_at INTEGER DEFAULT 0);
CREATE TABLE traffic_hourly (id INTEGER PRIMARY KEY AUTOINCREMENT, access_key_id TEXT, traffic REAL, recorded_at INTEGER);
CREATE TABLE traffic_daily (id INTEGER PRIMARY KEY AUTOINCREMENT, access_key_id TEXT, traffic REAL, recorded_at INTEGER);
INSERT INTO accounts(id,access_key_id) VALUES(7,'legacy-ak');
INSERT INTO traffic_hourly(access_key_id,traffic,recorded_at) VALUES('legacy-ak',12.5,100);
INSERT INTO traffic_daily(access_key_id,traffic,recorded_at) VALUES('legacy-ak',25,200);
`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var accountID int64
	if err = st.db.QueryRow(`SELECT account_id FROM traffic_hourly LIMIT 1`).Scan(&accountID); err != nil || accountID != 7 {
		t.Fatalf("hourly account_id=%d err=%v", accountID, err)
	}
	if err = st.db.QueryRow(`SELECT account_id FROM traffic_daily LIMIT 1`).Scan(&accountID); err != nil || accountID != 7 {
		t.Fatalf("daily account_id=%d err=%v", accountID, err)
	}
}
