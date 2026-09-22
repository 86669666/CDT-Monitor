package store

import (
	"context"
	"database/sql"
	"encoding/json"
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

func insertTestAccount(t *testing.T, st *Store, id int64) {
	t.Helper()
	if _, err := st.db.Exec(`INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status,max_traffic) VALUES(?,?,?,?,?,?,?)`, id, "LTAI"+strconv.FormatInt(id, 10), "cn-hongkong", "i-test", "china", "Unknown", 200); err != nil {
		t.Fatal(err)
	}
}

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

func TestGetConfigRejectsOversizedSetting(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES('timezone',?)`, strings.Repeat("z", maxSettingValueBytes+1)); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "setting is too large") {
		t.Fatalf("err=%v", err)
	}
}

func TestGetConfigRejectsInvalidSettingKey(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES('','poison')`); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "setting key is invalid") {
		t.Fatalf("empty key err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET key='   ' WHERE key=''`); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "setting key is invalid") {
		t.Fatalf("blank key err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET key=' timezone' WHERE key='   '`); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "setting key is invalid") {
		t.Fatalf("padded key err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET key=? WHERE key=' timezone'`, "time\nzone"); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "setting key is invalid") {
		t.Fatalf("broken key err=%v", err)
	}
}

func TestPutSettingTxRejectsOversizedValue(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	err = st.WithTx(ctx, func(tx *sql.Tx) error {
		return putSettingTx(ctx, tx, "timezone", strings.Repeat("z", maxSettingValueBytes+1))
	})
	if err == nil || !strings.Contains(err.Error(), "setting is too large") {
		t.Fatalf("value err=%v", err)
	}
	err = st.WithTx(ctx, func(tx *sql.Tx) error {
		return putSettingTx(ctx, tx, strings.Repeat("k", maxSettingKeyRunes+1), "ok")
	})
	if err == nil || !strings.Contains(err.Error(), "setting is too large") {
		t.Fatalf("key err=%v", err)
	}
}

func TestPutSettingTxRejectsInvalidKey(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	for _, key := range []string{"", "   ", " timezone", "time\nzone"} {
		err = st.WithTx(ctx, func(tx *sql.Tx) error {
			return putSettingTx(ctx, tx, key, "ok")
		})
		if err == nil || !strings.Contains(err.Error(), "setting key is invalid") {
			t.Fatalf("key=%q err=%v", key, err)
		}
	}
	var count int
	if err = st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM settings WHERE key IN (?,?,?,?)`, "", "   ", " timezone", "time\nzone").Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid keys persisted count=%d err=%v", count, err)
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
	config.Accounts[0].Remark = "bad\nnote"
	if err = st.SaveConfig(ctx, config); err == nil || !strings.Contains(err.Error(), "account remark is invalid") {
		t.Fatalf("broken remark err=%v", err)
	}
	accounts, err = st.ListAccounts(ctx)
	if err != nil || len(accounts) != 1 || accounts[0].Remark != strings.Repeat("备", maxAccountRemarkRunes) {
		t.Fatalf("broken remark must not persist, accounts=%#v err=%v", accounts, err)
	}
}

func TestListAccountsRejectsNonPositiveID(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status) VALUES(0,'LTAItest','cn-hongkong','i-test','china','Unknown')`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAccounts(ctx)
	if err == nil || !strings.Contains(err.Error(), "account id is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestListAccountsRejectsOversizedRemark(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(access_key_id,region_id,instance_id,remark,site_type,instance_status) VALUES('LTAItest','cn-hongkong','i-test',?,'china','Unknown')`, strings.Repeat("备", maxAccountRemarkRunes+1)); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAccounts(ctx)
	if err == nil || !strings.Contains(err.Error(), "remark is too long") {
		t.Fatalf("err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `DELETE FROM accounts`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(access_key_id,region_id,instance_id,remark,site_type,instance_status) VALUES('LTAItest','cn-hongkong','i-test',?,'china','Unknown')`, "bad\nnote"); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAccounts(ctx)
	if err == nil || !strings.Contains(err.Error(), "account remark is invalid") {
		t.Fatalf("broken remark err=%v", err)
	}
}

func TestListAccountsRejectsInvalidStatus(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(access_key_id,region_id,instance_id,site_type,instance_status) VALUES('LTAItest','cn-hongkong','i-test','china','exploded')`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAccounts(ctx)
	if err == nil || !strings.Contains(err.Error(), "instance status is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestListAccountsRejectsInvalidSiteType(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(access_key_id,region_id,instance_id,site_type,instance_status) VALUES('LTAItest','cn-hongkong','i-test','evil','Unknown')`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAccounts(ctx)
	if err == nil || !strings.Contains(err.Error(), "site_type is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestListAccountsRejectsInvalidIdentifiers(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(access_key_id,region_id,instance_id,site_type,instance_status) VALUES('LTAItest','cn-hongkong.evil','i-test','china','Unknown')`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAccounts(ctx)
	if err == nil || !strings.Contains(err.Error(), "region_id is invalid") {
		t.Fatalf("region err=%v", err)
	}
}

func TestListAccountsRejectsInvalidScheduleClock(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(access_key_id,region_id,instance_id,site_type,instance_status,start_time) VALUES('LTAItest','cn-hongkong','i-test','china','Unknown','25:61')`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAccounts(ctx)
	if err == nil || !strings.Contains(err.Error(), "schedule time is invalid") {
		t.Fatalf("err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE accounts SET start_time=' 09:00'`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAccounts(ctx)
	if err == nil || !strings.Contains(err.Error(), "schedule time is invalid") {
		t.Fatalf("padded clock err=%v", err)
	}
}

func TestListAccountsRejectsInvalidTraffic(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(access_key_id,region_id,instance_id,site_type,instance_status,traffic_used) VALUES('LTAItest','cn-hongkong','i-test','china','Unknown',-1)`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAccounts(ctx)
	if err == nil || !strings.Contains(err.Error(), "traffic sample is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestListAccountsRejectsInvalidMaxTraffic(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(access_key_id,region_id,instance_id,site_type,instance_status,max_traffic) VALUES('LTAItest','cn-hongkong','i-test','china','Unknown',-1)`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAccounts(ctx)
	if err == nil || !strings.Contains(err.Error(), "max traffic is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestListAccountsRejectsInvalidTimestamp(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(access_key_id,region_id,instance_id,site_type,instance_status,updated_at) VALUES('LTAItest','cn-hongkong','i-test','china','Unknown',-1)`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAccounts(ctx)
	if err == nil || !strings.Contains(err.Error(), "account timestamp is invalid") {
		t.Fatalf("updated_at err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE accounts SET updated_at=0,last_keep_alive_at=-1`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAccounts(ctx)
	if err == nil || !strings.Contains(err.Error(), "account timestamp is invalid") {
		t.Fatalf("keep_alive err=%v", err)
	}
}

func TestListAccountsRejectsInvalidSchedule(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(access_key_id,region_id,instance_id,site_type,instance_status,schedule_enabled) VALUES('LTAItest','cn-hongkong','i-test','china','Unknown',2)`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAccounts(ctx)
	if err == nil || !strings.Contains(err.Error(), "account schedule is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestAccountLookupsRejectNonPositiveID(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.GetAccount(ctx, 0); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("get account err=%v", err)
	}
	if _, err = st.AccountSecret(ctx, 0); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("secret err=%v", err)
	}
	if _, err = st.History(ctx, 0); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("history err=%v", err)
	}
	if err = st.UpdateRuntime(ctx, 0, 1, domain.StatusRunning, time.Now().UTC()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("runtime err=%v", err)
	}
}

func TestAccountSecretRejectsEmptyAndDeleted(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	insertTestAccount(t, st, 1)
	if _, err = st.GetAccount(ctx, 2); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing get err=%v", err)
	}
	if _, err = st.AccountSecret(ctx, 1); err == nil || !strings.Contains(err.Error(), "missing access key secret") {
		t.Fatalf("empty secret err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE accounts SET access_key_id='', access_key_secret='blob' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.AccountSecret(ctx, 1); err == nil || !strings.Contains(err.Error(), "access_key_id is invalid") {
		t.Fatalf("empty access key err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE accounts SET deleted_at=unixepoch() WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.AccountSecret(ctx, 1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted secret err=%v", err)
	}
	if _, err = st.GetAccount(ctx, 1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted get err=%v", err)
	}
}

func TestAccountWritesRejectNonPositiveID(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err = st.AddTrafficStats(ctx, 0, 1, time.Now().UTC()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("traffic err=%v", err)
	}
	if err = st.SetBillingCache(ctx, 0, "balance", "", map[string]float64{"amount": 1}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("set billing err=%v", err)
	}
	ok, err := st.BillingCache(ctx, 0, "balance", "", time.Hour, &map[string]any{})
	if ok || !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("get billing ok=%v err=%v", ok, err)
	}
	if _, err = st.RecordActionEvent(ctx, "threshold:1:active", 0, "threshold", "detected", ""); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("action event err=%v", err)
	}
	if err = st.UpdateKeepAliveAt(ctx, 0, time.Now().UTC()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("keepalive err=%v", err)
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

func TestAccountSecretsSkipsInvalidIdentifiers(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{
		AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging",
		ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai",
		Accounts: []domain.Account{{AccessKeyID: "LTAIkeep", AccessKeySecret: "keep-secret-value", RegionID: "cn-hongkong", InstanceID: "i-keep", MaxTraffic: 200, SiteType: "china"}},
	}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(access_key_id,access_key_secret,region_id,instance_id,site_type,instance_status,max_traffic) VALUES('','not-a-ciphertext','cn-hongkong','i-bad','china','Unknown',200)`); err != nil {
		t.Fatal(err)
	}
	secrets, err := st.AccountSecrets(ctx)
	if err != nil || len(secrets) != 1 || secrets[0] != "keep-secret-value" {
		t.Fatalf("invalid identifier must be skipped: %#v err=%v", secrets, err)
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

func TestGetConfigRejectsInvalidNumericSetting(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai"}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		key   string
		reset string
	}{
		{key: "api_interval", reset: "600"},
		{key: "traffic_threshold", reset: "95"},
		{key: "notify_port", reset: "465"},
	}
	for _, tc := range cases {
		if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value='abc' WHERE key=?`, tc.key); err != nil {
			t.Fatal(err)
		}
		_, err = st.GetConfig(ctx)
		if err == nil || !strings.Contains(err.Error(), "setting "+tc.key+" is invalid") {
			t.Fatalf("%s err=%v", tc.key, err)
		}
		if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value=? WHERE key=?`, tc.reset, tc.key); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGetConfigRejectsInvalidBooleanSetting(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai"}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		key   string
		reset string
	}{
		{key: "keep_alive", reset: "false"},
		{key: "enable_billing", reset: "false"},
		{key: "enable_schedule_email", reset: "false"},
		{key: "notify_email_enabled", reset: "true"},
		{key: "notify_tg_enabled", reset: "false"},
		{key: "notify_wh_enabled", reset: "false"},
	}
	for _, tc := range cases {
		if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value='yes' WHERE key=?`, tc.key); err != nil {
			t.Fatal(err)
		}
		_, err = st.GetConfig(ctx)
		if err == nil || !strings.Contains(err.Error(), "setting "+tc.key+" is invalid") {
			t.Fatalf("%s err=%v", tc.key, err)
		}
		if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value=? WHERE key=?`, tc.reset, tc.key); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGetConfigRejectsOutOfRangeNumericSetting(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai"}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		key   string
		value string
		err   string
		reset string
	}{
		{key: "traffic_threshold", value: "0", err: "traffic threshold must be between 1 and 100", reset: "95"},
		{key: "traffic_threshold", value: "101", err: "traffic threshold must be between 1 and 100", reset: "95"},
		{key: "notify_port", value: "-1", err: "notification port is invalid", reset: "465"},
		{key: "notify_port", value: "65536", err: "notification port is invalid", reset: "465"},
		{key: "api_interval", value: "86401", err: "api interval must be between 30 and 86400 seconds", reset: "600"},
	}
	for _, tc := range cases {
		if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value=? WHERE key=?`, tc.value, tc.key); err != nil {
			t.Fatal(err)
		}
		_, err = st.GetConfig(ctx)
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Fatalf("%s=%s err=%v", tc.key, tc.value, err)
		}
		if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value=? WHERE key=?`, tc.reset, tc.key); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := st.GetConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TrafficThreshold != 95 || loaded.APIInterval != 600 || loaded.Notifications.Email.Port != 465 {
		t.Fatalf("restored config = %#v", loaded)
	}
}

func TestGetConfigRejectsInvalidActionSettings(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai"}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		key   string
		value string
		err   string
		reset string
	}{
		{key: "shutdown_mode", value: "Reboot", err: "invalid shutdown mode", reset: "KeepCharging"},
		{key: "threshold_action", value: "stop_only", err: "invalid threshold action", reset: "stop_and_notify"},
	}
	for _, tc := range cases {
		if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value=? WHERE key=?`, tc.value, tc.key); err != nil {
			t.Fatal(err)
		}
		_, err = st.GetConfig(ctx)
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Fatalf("%s=%s err=%v", tc.key, tc.value, err)
		}
		if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value=? WHERE key=?`, tc.reset, tc.key); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGetConfigRejectsInvalidTimezone(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai"}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value='Not/AZone' WHERE key='timezone'`); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "invalid timezone") {
		t.Fatalf("invalid timezone err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value=? WHERE key='timezone'`, strings.Repeat("A", maxTimezoneRunes+1)); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "invalid timezone") {
		t.Fatalf("oversized timezone err=%v", err)
	}
}

func TestGetConfigRejectsInvalidNotifyOptions(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai"}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		key   string
		value string
		reset string
	}{
		{key: "notify_wh_method", value: "DELETE", reset: "GET"},
		{key: "notify_secure", value: "none", reset: "ssl"},
		{key: "notify_tg_proxy_type", value: "http", reset: "none"},
		{key: "notify_wh_request_type", value: "XML", reset: "JSON"},
		{key: "notify_wh_provider", value: "slack", reset: "generic"},
		{key: "notify_secure", value: "ssl\n", reset: "ssl"},
		{key: "notify_wh_method", value: " GET", reset: "GET"},
	}
	for _, tc := range cases {
		if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value=? WHERE key=?`, tc.value, tc.key); err != nil {
			t.Fatal(err)
		}
		_, err = st.GetConfig(ctx)
		if err == nil || !strings.Contains(err.Error(), "notification option is invalid") {
			t.Fatalf("%s=%s err=%v", tc.key, tc.value, err)
		}
		if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value=? WHERE key=?`, tc.reset, tc.key); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGetConfigRejectsInvalidNotifyProxyPort(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai"}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"0", "-1", "65536", "abc"} {
		if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value=? WHERE key='notify_tg_proxy_port'`, value); err != nil {
			t.Fatal(err)
		}
		_, err = st.GetConfig(ctx)
		if err == nil || !strings.Contains(err.Error(), "notification port is invalid") {
			t.Fatalf("proxy port %q err=%v", value, err)
		}
	}
}

func TestGetConfigRejectsForbiddenNotifyDestinations(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai"}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value='100.100.100.200' WHERE key='notify_host'`); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "notification URL host is not allowed") {
		t.Fatalf("smtp host err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value='' WHERE key='notify_host'`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value='100.100.100.200' WHERE key='notify_tg_proxy_ip'`); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "notification URL host is not allowed") {
		t.Fatalf("proxy ip err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value='' WHERE key='notify_tg_proxy_ip'`); err != nil {
		t.Fatal(err)
	}
	encrypted, err := st.EncryptAAD("file:///etc/passwd", "notify_wh_url")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES('notify_wh_url',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, encrypted); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "notification URL must use http or https") {
		t.Fatalf("webhook url err=%v", err)
	}
}

func TestGetConfigRejectsInvalidNotifyIdentities(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai"}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value=? WHERE key='notify_email'`, "alerts\nroot@example.test"); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "notification header fields must not contain line breaks") {
		t.Fatalf("email header err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value='' WHERE key='notify_email'`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value=? WHERE key='notify_username'`, strings.Repeat("u", 255)); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "notification identity is too long") {
		t.Fatalf("username err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value='' WHERE key='notify_username'`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value=? WHERE key='notify_tg_chat_id'`, strings.Repeat("1", 65)); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "notification identity is too long") {
		t.Fatalf("chat id err=%v", err)
	}
}

func TestGetConfigRejectsInvalidNotifyPayloads(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai"}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value=? WHERE key='notify_tg_proxy_user'`, "user\nadmin"); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "notification header fields must not contain line breaks") {
		t.Fatalf("proxy user err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value='' WHERE key='notify_tg_proxy_user'`); err != nil {
		t.Fatal(err)
	}
	headers, err := st.EncryptAAD("{\"X-Bad\":\"a\\nb\"}", "notify_wh_headers")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES('notify_wh_headers',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, headers); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "notification header fields must not contain line breaks") {
		t.Fatalf("headers err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE settings SET value='' WHERE key='notify_wh_headers'`); err != nil {
		t.Fatal(err)
	}
	body, err := st.EncryptAAD(strings.Repeat("b", 8193), "notify_wh_body")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES('notify_wh_body',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, body); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "notification payload is too long") {
		t.Fatalf("body err=%v", err)
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

func TestListAPIKeysRejectsInvalidTimestamp(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO api_keys(name,token_hash,scopes,created_at) VALUES('zero','hash-zero','["widget:read"]',0)`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "api key timestamp is invalid") {
		t.Fatalf("created_at err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `DELETE FROM api_keys`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO api_keys(name,token_hash,scopes,created_at,expires_at) VALUES('expired-zero','hash-exp','["widget:read"]',unixepoch(),0)`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "api key timestamp is invalid") {
		t.Fatalf("expires_at err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `DELETE FROM api_keys`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO api_keys(name,token_hash,scopes,created_at,last_used_at) VALUES('used-zero','hash-used','["widget:read"]',unixepoch(),-1)`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "api key timestamp is invalid") {
		t.Fatalf("last_used_at err=%v", err)
	}
}

func TestListAPIKeysRejectsNonPositiveID(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO api_keys(id,name,token_hash,scopes,created_at) VALUES(0,'zero','hash-zero-id','["widget:read"]',unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "api key id is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestListAPIKeysRejectsInvalidName(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO api_keys(name,token_hash,scopes,created_at) VALUES('   ','hash-blank','["widget:read"]',unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "api key name is invalid") {
		t.Fatalf("blank name err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `DELETE FROM api_keys`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO api_keys(name,token_hash,scopes,created_at) VALUES(?,'hash-long','["widget:read"]',unixepoch())`, strings.Repeat("n", maxAPIKeyNameRunes+1)); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "api key name is invalid") {
		t.Fatalf("long name err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `DELETE FROM api_keys`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO api_keys(name,token_hash,scopes,created_at) VALUES(?,'hash-break','["widget:read"]',unixepoch())`, "bad\nname"); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "api key name is invalid") {
		t.Fatalf("broken name err=%v", err)
	}
}

func TestListAPIKeysRejectsUnknownScopes(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO api_keys(name,token_hash,scopes,created_at) VALUES('admin','hash-admin','["admin"]',unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "invalid API key scope") {
		t.Fatalf("admin scope err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE api_keys SET scopes='["widget:read","admin"]'`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "invalid API key scope") {
		t.Fatalf("mixed scope err=%v", err)
	}
}

func TestListAPIKeysRejectsDuplicateScopes(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO api_keys(name,token_hash,scopes,created_at) VALUES('dup','hash-dup','["widget:read","widget:read"]',unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "invalid API key scope") {
		t.Fatalf("duplicate scope err=%v", err)
	}
}

func TestListAPIKeysRejectsEmptyScopes(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO api_keys(name,token_hash,scopes,created_at) VALUES('empty','hash-empty','[""]',unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "invalid API key scope") {
		t.Fatalf("empty scope err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE api_keys SET scopes='["widget:read",""]'`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "invalid API key scope") {
		t.Fatalf("mixed empty scope err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE api_keys SET scopes='[" "]'`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "invalid API key scope") {
		t.Fatalf("blank scope err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE api_keys SET scopes='null'`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "invalid API key scope") {
		t.Fatalf("null scopes err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE api_keys SET scopes='[]'`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "invalid API key scope") {
		t.Fatalf("empty scope list err=%v", err)
	}
}

func TestListAPIKeysRejectsPaddedScopes(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO api_keys(name,token_hash,scopes,created_at) VALUES('pad','hash-pad','[" widget:read"]',unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "invalid API key scope") {
		t.Fatalf("padded scope err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE api_keys SET scopes='["widget:read"," widget:read"]'`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListAPIKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "invalid API key scope") {
		t.Fatalf("mixed padded scope err=%v", err)
	}
}

func TestCreateAPIKeyReturnsPositiveID(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key, token, err := st.CreateAPIKey(context.Background(), "widget", []string{"widget:read"}, nil)
	if err != nil || key.ID < 1 || token == "" {
		t.Fatalf("key=%#v token=%q err=%v", key, token, err)
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

func TestAddLogFlattensTextBreaks(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err = st.AddLog(ctx, "error", "line\r\none\x00two"); err != nil {
		t.Fatal(err)
	}
	entries, err := st.ListLogs(ctx, "action", 10)
	if err != nil || len(entries) != 1 || entries[0].Message != "line  one two" {
		t.Fatalf("written=%#v err=%v", entries, err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO logs(type,message,created_at) VALUES('audit',?,unixepoch())`, "keep\nme"); err != nil {
		t.Fatal(err)
	}
	entries, err = st.ListLogs(ctx, "action", 10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("listed=%#v err=%v", entries, err)
	}
	if entries[0].Message != "keep me" {
		t.Fatalf("stored poison listed as %q", entries[0].Message)
	}
}

func TestListLogsClipsOversizedStoredMessages(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO logs(type,message,created_at) VALUES('error',?,unixepoch())`, strings.Repeat("x", maxLogRunes+64)); err != nil {
		t.Fatal(err)
	}
	entries, err := st.ListLogs(ctx, "action", 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("logs=%#v err=%v", entries, err)
	}
	if got := []rune(entries[0].Message); len(got) != maxLogRunes {
		t.Fatalf("listed log len = %d", len(got))
	}
}

func TestListLogsRejectsInvalidStoredRows(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO logs(type,message,created_at) VALUES('error','boom',0)`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListLogs(ctx, "action", 10)
	if err == nil || !strings.Contains(err.Error(), "log timestamp is invalid") {
		t.Fatalf("timestamp err=%v", err)
	}
}

func TestListLogsRejectsNonPositiveID(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO logs(id,type,message,created_at) VALUES(0,'error','boom',unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListLogs(ctx, "action", 10)
	if err == nil || !strings.Contains(err.Error(), "log id is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestListLogsRejectsInvalidTab(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err = st.AddLog(ctx, "error", "boom"); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListLogs(ctx, "debug", 10)
	if err == nil || !strings.Contains(err.Error(), "log tab is invalid") {
		t.Fatalf("list err=%v", err)
	}
	if err = st.ClearLogs(ctx, "debug"); err == nil || !strings.Contains(err.Error(), "log tab is invalid") {
		t.Fatalf("clear err=%v", err)
	}
	entries, err := st.ListLogs(ctx, "action", 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("valid tab logs=%#v err=%v", entries, err)
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
	if _, err = st.AcquireLease(ctx, "   ", "owner-a", time.Minute); err == nil || !strings.Contains(err.Error(), "lease identity is invalid") {
		t.Fatalf("blank name err=%v", err)
	}
	if _, err = st.AcquireLease(ctx, " monitor", "owner-a", time.Minute); err == nil || !strings.Contains(err.Error(), "lease identity is invalid") {
		t.Fatalf("padded name err=%v", err)
	}
	if _, err = st.AcquireLease(ctx, "monitor", " owner-a", time.Minute); err == nil || !strings.Contains(err.Error(), "lease identity is invalid") {
		t.Fatalf("padded owner err=%v", err)
	}
	if _, err = st.AcquireLease(ctx, "mon\nitor", "owner-a", time.Minute); err == nil || !strings.Contains(err.Error(), "lease identity is invalid") {
		t.Fatalf("broken name err=%v", err)
	}
	if _, err = st.AcquireLease(ctx, "monitor", "own\ner-a", time.Minute); err == nil || !strings.Contains(err.Error(), "lease identity is invalid") {
		t.Fatalf("broken owner err=%v", err)
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

func TestAcquireLeaseRejectsInvalidTTL(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	for _, ttl := range []time.Duration{0, -time.Second} {
		got, err := st.AcquireLease(ctx, "monitor", "owner-a", ttl)
		if got || err == nil || !strings.Contains(err.Error(), "lease ttl is invalid") {
			t.Fatalf("ttl=%v got=%v err=%v", ttl, got, err)
		}
	}
	var count int
	if err = st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scheduler_leases`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid ttl must not store a lease, count=%d err=%v", count, err)
	}
}

func TestAcquireLeaseRejectsOversizedStoredOwner(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	expires := time.Now().Add(time.Hour).Unix()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO scheduler_leases(name,owner,expires_at,updated_at) VALUES('monitor',?,?,?)`, strings.Repeat("o", maxLeaseOwnerRunes+1), expires, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	_, err = st.AcquireLease(ctx, "monitor", "owner-b", time.Minute)
	if err == nil || !strings.Contains(err.Error(), "lease identity is invalid") {
		t.Fatalf("err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE scheduler_leases SET owner=' owner-a'`); err != nil {
		t.Fatal(err)
	}
	_, err = st.AcquireLease(ctx, "monitor", "owner-b", time.Minute)
	if err == nil || !strings.Contains(err.Error(), "lease identity is invalid") {
		t.Fatalf("padded stored owner err=%v", err)
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
	if _, err = st.RecordActionEvent(ctx, "   ", 1, "threshold", "detected", ""); err == nil || !strings.Contains(err.Error(), "key is invalid") {
		t.Fatalf("blank key err=%v", err)
	}
	if _, err = st.RecordActionEvent(ctx, " threshold:1:active", 1, "threshold", "detected", ""); err == nil || !strings.Contains(err.Error(), "key is invalid") {
		t.Fatalf("padded key err=%v", err)
	}
	if _, err = st.RecordActionEvent(ctx, "thresh\nold:1:active", 1, "threshold", "detected", ""); err == nil || !strings.Contains(err.Error(), "key is invalid") {
		t.Fatalf("broken key err=%v", err)
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
	if _, err = st.RecordActionEvent(ctx, "threshold:1:active", 1, "threshold", "detected", ""); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing account err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status,max_traffic) VALUES(1,'LTAItest','cn-hongkong','i-test','china','Unknown',200)`); err != nil {
		t.Fatal(err)
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

func TestRecordActionEventFlattensDetail(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	insertTestAccount(t, st, 1)
	fresh, err := st.RecordActionEvent(ctx, "threshold:1:active", 1, "threshold", "detected", "line\none\x00two")
	if err != nil || !fresh {
		t.Fatalf("fresh=%v err=%v", fresh, err)
	}
	var detail string
	if err = st.db.QueryRowContext(ctx, `SELECT detail FROM action_events WHERE event_key='threshold:1:active'`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if detail != "line one two" {
		t.Fatalf("detail=%q", detail)
	}
}

func TestDeleteActionEventRejectsInvalidKey(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err = st.DeleteActionEvent(ctx, ""); err == nil || !strings.Contains(err.Error(), "key is invalid") {
		t.Fatalf("empty key err=%v", err)
	}
	if err = st.DeleteActionEvent(ctx, "   "); err == nil || !strings.Contains(err.Error(), "key is invalid") {
		t.Fatalf("blank key err=%v", err)
	}
	if err = st.DeleteActionEvent(ctx, "thresh\nold:1"); err == nil || !strings.Contains(err.Error(), "key is invalid") {
		t.Fatalf("broken key err=%v", err)
	}
	if err = st.DeleteActionEvent(ctx, strings.Repeat("k", maxActionEventKeyRunes+1)); err == nil || !strings.Contains(err.Error(), "key is invalid") {
		t.Fatalf("long key err=%v", err)
	}
}

func TestActionEventCanBeReleasedAfterFailure(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status,max_traffic) VALUES(1,'LTAItest','cn-hongkong','i-test','china','Unknown',200)`); err != nil {
		t.Fatal(err)
	}
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

func TestRecordActionEventRequiresActiveAccount(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status,max_traffic,deleted_at) VALUES(1,'LTAItest','cn-hongkong','i-test','china','Unknown',200,unixepoch())`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.RecordActionEvent(ctx, "threshold:1:active", 1, "threshold", "detected", ""); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted account err=%v", err)
	}
	var count int
	if err = st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM action_events`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("deleted account must not store events, count=%d err=%v", count, err)
	}
}

func TestFailedJobRetriesThenReleasesUniqueKey(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	insertTestAccount(t, st, 1)
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

func TestGetJobRejectsOversizedID(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	insertTestAccount(t, st, 1)
	job, err := st.EnqueueJob(ctx, "refresh_account", 1, `{}`, "", 3)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetJob(ctx, job.ID)
	if err != nil || got.ID != job.ID {
		t.Fatalf("normal get = %#v err=%v", got, err)
	}
	if _, err = st.GetJob(ctx, ""); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("empty id err=%v", err)
	}
	if _, err = st.GetJob(ctx, strings.Repeat("j", maxJobIDBytes+1)); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("oversized id err=%v", err)
	}
	if _, err = st.GetJob(ctx, " "+job.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("padded id err=%v", err)
	}
	if _, err = st.GetJob(ctx, "job\n1"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("broken id err=%v", err)
	}
	if err = st.CompleteJob(ctx, strings.Repeat("j", maxJobIDBytes+1), "ok"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("complete oversized err=%v", err)
	}
	if err = st.CompleteJob(ctx, " "+job.ID, "ok"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("complete padded err=%v", err)
	}
	if err = st.CompleteJob(ctx, "job\n1", "ok"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("complete broken err=%v", err)
	}
	var status string
	if err = st.db.QueryRowContext(ctx, `SELECT status FROM jobs WHERE id=?`, job.ID).Scan(&status); err != nil || status != "queued" {
		t.Fatalf("invalid id must not complete job, status=%q err=%v", status, err)
	}
}

func TestGetJobRejectsOversizedPayload(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	id := "job-oversized-payload"
	blob := strings.Repeat("x", maxJobPayloadRunes+1)
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,max_attempts,available_at,created_at,updated_at) VALUES(?,?,1,?,'queued',3,unixepoch(),unixepoch(),unixepoch())`, id, "refresh_account", blob); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetJob(ctx, id)
	if err == nil || !strings.Contains(err.Error(), "payload is too long") {
		t.Fatalf("err=%v", err)
	}
}

func TestGetJobRejectsInvalidPayload(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	id := "job-bad-payload"
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,max_attempts,available_at,created_at,updated_at) VALUES(?,?,1,'{','queued',3,unixepoch(),unixepoch(),unixepoch())`, id, "refresh_account"); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetJob(ctx, id)
	if err == nil || !strings.Contains(err.Error(), "payload is invalid") {
		t.Fatalf("err=%v", err)
	}
	var status string
	if err = st.db.QueryRowContext(ctx, `SELECT status FROM jobs WHERE id=?`, id).Scan(&status); err != nil || status != "queued" {
		t.Fatalf("get must not mutate stored job, status=%q err=%v", status, err)
	}
}

func TestGetJobRejectsInvalidStoredItem(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,max_attempts,available_at,created_at,updated_at) VALUES('job-unknown','wipe_disk',1,'{}','queued',3,unixepoch(),unixepoch(),unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetJob(ctx, "job-unknown")
	if err == nil || !strings.Contains(err.Error(), "job type is invalid") {
		t.Fatalf("unknown type err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,max_attempts,available_at,created_at,updated_at) VALUES('job-no-account','refresh_account',0,'{}','queued',3,unixepoch(),unixepoch(),unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetJob(ctx, "job-no-account")
	if err == nil || !strings.Contains(err.Error(), "account id is invalid") {
		t.Fatalf("account id err=%v", err)
	}
	var status string
	if err = st.db.QueryRowContext(ctx, `SELECT status FROM jobs WHERE id='job-unknown'`).Scan(&status); err != nil || status != "queued" {
		t.Fatalf("get must not mutate stored job, status=%q err=%v", status, err)
	}
}

func TestGetJobRejectsInvalidStatus(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,max_attempts,available_at,created_at,updated_at) VALUES('job-bad-status','refresh_account',1,'{}','exploded',3,unixepoch(),unixepoch(),unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetJob(ctx, "job-bad-status")
	if err == nil || !strings.Contains(err.Error(), "job status is invalid") {
		t.Fatalf("err=%v", err)
	}
	var status string
	if err = st.db.QueryRowContext(ctx, `SELECT status FROM jobs WHERE id='job-bad-status'`).Scan(&status); err != nil || status != "exploded" {
		t.Fatalf("get must not mutate stored job, status=%q err=%v", status, err)
	}
}

func TestGetJobRejectsInvalidTimestamp(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,max_attempts,available_at,created_at,updated_at) VALUES('job-bad-ts','refresh_account',1,'{}','queued',3,0,unixepoch(),unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetJob(ctx, "job-bad-ts")
	if err == nil || !strings.Contains(err.Error(), "job timestamp is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestGetJobRejectsInvalidAttempts(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,attempts,max_attempts,available_at,created_at,updated_at) VALUES('job-bad-attempts','refresh_account',1,'{}','queued',-1,3,unixepoch(),unixepoch(),unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetJob(ctx, "job-bad-attempts")
	if err == nil || !strings.Contains(err.Error(), "job attempts are invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestGetJobRejectsMissingAccount(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,max_attempts,available_at,created_at,updated_at) VALUES('job-missing-account','refresh_account',1,'{}','queued',3,unixepoch(),unixepoch(),unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetJob(ctx, "job-missing-account")
	if err == nil || !strings.Contains(err.Error(), "account id is invalid") {
		t.Fatalf("err=%v", err)
	}
	var status string
	if err = st.db.QueryRowContext(ctx, `SELECT status FROM jobs WHERE id='job-missing-account'`).Scan(&status); err != nil || status != "queued" {
		t.Fatalf("get must not mutate stored job, status=%q err=%v", status, err)
	}
}

func TestGetJobClipsOversizedResultAndError(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	insertTestAccount(t, st, 1)
	id := "job-oversized-result"
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,result,error,max_attempts,available_at,created_at,updated_at) VALUES(?,?,1,'{}','failed',?,?,3,unixepoch(),unixepoch(),unixepoch())`, id, "refresh_account", strings.Repeat("r", maxLogRunes+8), strings.Repeat("e", maxLogRunes+8)); err != nil {
		t.Fatal(err)
	}
	job, err := st.GetJob(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got := []rune(job.Result); len(got) != maxLogRunes {
		t.Fatalf("result len=%d", len(got))
	}
	if got := []rune(job.Error); len(got) != maxLogRunes {
		t.Fatalf("error len=%d", len(got))
	}
}

func TestJobAndOutboxTextBreaksAreFlattened(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	id := "job-break"
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,max_attempts,available_at,created_at,updated_at) VALUES(?,'test_notification',0,'{}','running',3,unixepoch(),unixepoch(),unixepoch())`, id); err != nil {
		t.Fatal(err)
	}
	if err = st.CompleteJob(ctx, id, "line\none"); err != nil {
		t.Fatal(err)
	}
	job, err := st.GetJob(ctx, id)
	if err != nil || job.Result != "line one" {
		t.Fatalf("result=%q err=%v", job.Result, err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE jobs SET status='running',error='' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if err = st.FailJob(ctx, domain.Job{ID: id, Attempts: 3, MaxAttempts: 3}, errors.New("bad\r\nerr")); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err = st.db.QueryRowContext(ctx, `SELECT error FROM jobs WHERE id=?`, id).Scan(&stored); err != nil || stored != "bad  err" {
		t.Fatalf("job error=%q err=%v", stored, err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO notification_outbox(id,event_id,channel,payload,status,attempts,max_attempts,available_at,created_at,updated_at) VALUES('evt-break:email','evt-break','email','{"id":"evt-break","type":"threshold","title":"t","summary":"s"}','sending',1,3,unixepoch(),unixepoch(),unixepoch())`); err != nil {
		t.Fatal(err)
	}
	if err = st.FailOutbox(ctx, OutboxItem{ID: "evt-break:email", Attempts: 3, MaxAttempts: 3}, errors.New("out\nbox")); err != nil {
		t.Fatal(err)
	}
	if err = st.db.QueryRowContext(ctx, `SELECT last_error FROM notification_outbox WHERE id='evt-break:email'`).Scan(&stored); err != nil || stored != "out box" {
		t.Fatalf("outbox error=%q err=%v", stored, err)
	}
}

func TestClaimJobFailsOversizedPayload(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	id := "job-claim-oversized-payload"
	blob := strings.Repeat("x", maxJobPayloadRunes+1)
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,max_attempts,available_at,created_at,updated_at) VALUES(?,?,1,?,'queued',3,unixepoch(),unixepoch(),unixepoch())`, id, "refresh_account", blob); err != nil {
		t.Fatal(err)
	}
	_, err = st.ClaimJob(ctx)
	if err == nil || !strings.Contains(err.Error(), "payload is too long") {
		t.Fatalf("err=%v", err)
	}
	var status, jobErr string
	if err = st.db.QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id=?`, id).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(jobErr, "payload is too long") {
		t.Fatalf("status=%q error=%q", status, jobErr)
	}
}

func TestClaimJobFailsInvalidPayload(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	id := "job-claim-bad-payload"
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,max_attempts,available_at,created_at,updated_at) VALUES(?,?,1,'{','queued',3,unixepoch(),unixepoch(),unixepoch())`, id, "refresh_account"); err != nil {
		t.Fatal(err)
	}
	_, err = st.ClaimJob(ctx)
	if err == nil || !strings.Contains(err.Error(), "payload is invalid") {
		t.Fatalf("err=%v", err)
	}
	var status, jobErr string
	if err = st.db.QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id=?`, id).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(jobErr, "payload is invalid") {
		t.Fatalf("status=%q error=%q", status, jobErr)
	}
}

func TestClaimJobFailsInvalidStoredItem(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	cases := []struct {
		id        string
		jobType   string
		accountID int64
		err       string
	}{
		{id: "job-unknown-type", jobType: "wipe_disk", accountID: 1, err: "job type is invalid"},
		{id: "job-missing-account", jobType: "refresh_account", accountID: 0, err: "account id is invalid"},
		{id: " job-pad", jobType: "refresh_account", accountID: 1, err: "job id is invalid"},
		{id: "job\nbroken", jobType: "refresh_account", accountID: 1, err: "job id is invalid"},
	}
	for _, tc := range cases {
		if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,max_attempts,available_at,created_at,updated_at) VALUES(?,?,?,?,'queued',3,unixepoch(),unixepoch(),unixepoch())`, tc.id, tc.jobType, tc.accountID, `{}`); err != nil {
			t.Fatal(err)
		}
		_, err = st.ClaimJob(ctx)
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Fatalf("%s err=%v", tc.id, err)
		}
		var status, jobErr string
		if err = st.db.QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id=?`, tc.id).Scan(&status, &jobErr); err != nil {
			t.Fatal(err)
		}
		if status != "failed" || !strings.Contains(jobErr, tc.err) {
			t.Fatalf("%s status=%q error=%q", tc.id, status, jobErr)
		}
	}
	if _, err = st.ClaimJob(ctx); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("poisoned jobs must not stay queued: err=%v", err)
	}
}

func TestClaimJobFailsMissingAccount(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,max_attempts,available_at,created_at,updated_at) VALUES('job-missing-account','refresh_account',1,'{}','queued',3,unixepoch(),unixepoch(),unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ClaimJob(ctx)
	if err == nil || !strings.Contains(err.Error(), "account id is invalid") {
		t.Fatalf("err=%v", err)
	}
	var status, jobErr string
	if err = st.db.QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id='job-missing-account'`).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(jobErr, "account id is invalid") {
		t.Fatalf("status=%q error=%q", status, jobErr)
	}
}

func TestClaimJobFailsInvalidTimestamp(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,max_attempts,available_at,created_at,updated_at) VALUES('job-bad-ts','refresh_account',1,'{}','queued',3,unixepoch(),0,unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ClaimJob(ctx)
	if err == nil || !strings.Contains(err.Error(), "job timestamp is invalid") {
		t.Fatalf("err=%v", err)
	}
	var status, jobErr string
	if err = st.db.QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id='job-bad-ts'`).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(jobErr, "job timestamp is invalid") {
		t.Fatalf("status=%q error=%q", status, jobErr)
	}
}

func TestFailJobRejectsInvalidIDAndNilError(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	insertTestAccount(t, st, 1)
	if err = st.FailJob(ctx, domain.Job{}, errors.New("boom")); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("empty id err=%v", err)
	}
	if err = st.FailJob(ctx, domain.Job{ID: strings.Repeat("j", maxJobIDBytes+1)}, errors.New("boom")); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("oversized id err=%v", err)
	}
	if err = st.FailJob(ctx, domain.Job{ID: " job-pad"}, errors.New("boom")); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("padded id err=%v", err)
	}
	if err = st.FailJob(ctx, domain.Job{ID: "job\n1"}, errors.New("boom")); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("broken id err=%v", err)
	}
	job, err := st.EnqueueJob(ctx, "refresh_account", 1, `{}`, "", 3)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.FailJob(ctx, job, nil); err == nil || !strings.Contains(err.Error(), "job error is required") {
		t.Fatalf("nil error err=%v", err)
	}
	job.Attempts = -1
	if err = st.FailJob(ctx, job, errors.New("boom")); err == nil || !strings.Contains(err.Error(), "job attempts are invalid") {
		t.Fatalf("negative attempts err=%v", err)
	}
	var status string
	if err = st.db.QueryRowContext(ctx, `SELECT status FROM jobs WHERE id=?`, job.ID).Scan(&status); err != nil || status != "queued" {
		t.Fatalf("invalid fail must not mutate job, status=%q err=%v", status, err)
	}
	if err = st.FailJob(ctx, domain.Job{ID: "missing-job", Attempts: 1, MaxAttempts: 3}, errors.New("boom")); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing fail err=%v", err)
	}
	if err = st.CompleteJob(ctx, "missing-job", "ok"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing complete err=%v", err)
	}
}

func TestClaimJobFailsInvalidAttempts(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,attempts,max_attempts,available_at,created_at,updated_at) VALUES('job-bad-attempts','refresh_account',1,'{}','queued',-1,3,unixepoch(),unixepoch(),unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ClaimJob(ctx)
	if err == nil || !strings.Contains(err.Error(), "job attempts are invalid") {
		t.Fatalf("err=%v", err)
	}
	var status, jobErr string
	if err = st.db.QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id='job-bad-attempts'`).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(jobErr, "job attempts are invalid") {
		t.Fatalf("status=%q error=%q", status, jobErr)
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
	if _, err = st.EnqueueJob(ctx, strings.Repeat("t", maxJobTypeRunes), 1, `{}`, "", maxJobAttempts); err == nil || !strings.Contains(err.Error(), "job type is invalid") {
		t.Fatalf("unknown type err=%v", err)
	}
	if _, err = st.EnqueueJob(ctx, "refresh_account", 0, `{}`, "", 3); err == nil || !strings.Contains(err.Error(), "account id is invalid") {
		t.Fatalf("account id err=%v", err)
	}
	if _, err = st.EnqueueJob(ctx, "test_notification", 0, `{}`, "", 3); err != nil {
		t.Fatalf("test notify err=%v", err)
	}
}

func TestEnqueueJobRequiresActiveAccount(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.EnqueueJob(ctx, "refresh_account", 1, `{}`, "", 3); err == nil || !strings.Contains(err.Error(), "account id is invalid") {
		t.Fatalf("missing account err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status,max_traffic,deleted_at) VALUES(1,'LTAItest','cn-hongkong','i-test','china','Unknown',200,unixepoch())`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.EnqueueJob(ctx, "refresh_account", 1, `{}`, "", 3); err == nil || !strings.Contains(err.Error(), "account id is invalid") {
		t.Fatalf("deleted account err=%v", err)
	}
	var count int
	if err = st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("inactive account must not enqueue, count=%d err=%v", count, err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE accounts SET deleted_at=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.EnqueueJob(ctx, "refresh_account", 1, `{}`, "", 3); err != nil {
		t.Fatal(err)
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
	if _, err = st.EnqueueJob(ctx, "refresh_account", 1, `{`, "", 3); err == nil || !strings.Contains(err.Error(), "payload is invalid") {
		t.Fatalf("invalid json err=%v", err)
	}
	if _, err = st.EnqueueJob(ctx, "refresh_account", 1, `{}`, strings.Repeat("k", maxJobUniqueKeyRunes+1), 3); err == nil || !strings.Contains(err.Error(), "unique key is too long") {
		t.Fatalf("unique key err=%v", err)
	}
	if _, err = st.EnqueueJob(ctx, "refresh_account", 1, `{}`, " refresh:1 ", 3); err == nil || !strings.Contains(err.Error(), "unique key is invalid") {
		t.Fatalf("padded unique key err=%v", err)
	}
	if _, err = st.EnqueueJob(ctx, "refresh_account", 1, `{}`, "   ", 3); err == nil || !strings.Contains(err.Error(), "unique key is invalid") {
		t.Fatalf("blank unique key err=%v", err)
	}
	if _, err = st.EnqueueJob(ctx, "refresh_account", 1, `{}`, "mon\nitor:1", 3); err == nil || !strings.Contains(err.Error(), "unique key is invalid") {
		t.Fatalf("broken unique key err=%v", err)
	}
	var count int
	if err = st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid unique key must not enqueue, count=%d err=%v", count, err)
	}
	insertTestAccount(t, st, 1)
	maxPayload := `"` + strings.Repeat("x", maxJobPayloadRunes-2) + `"`
	if _, err = st.EnqueueJob(ctx, "refresh_account", 1, maxPayload, strings.Repeat("k", maxJobUniqueKeyRunes), 3); err != nil {
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
	insertTestAccount(t, st, 1)
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

func TestCreateSessionRejectsInvalidTTL(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	for _, ttl := range []time.Duration{0, -time.Second} {
		token, err := st.CreateSession(ctx, "127.0.0.1", "test", ttl)
		if token != "" || err == nil || !strings.Contains(err.Error(), "session ttl is invalid") {
			t.Fatalf("create ttl=%v token=%q err=%v", ttl, token, err)
		}
		token, err = st.CreateExclusiveSession(ctx, "127.0.0.1", "test", ttl)
		if token != "" || err == nil || !strings.Contains(err.Error(), "session ttl is invalid") {
			t.Fatalf("exclusive ttl=%v token=%q err=%v", ttl, token, err)
		}
	}
	var count int
	if err = st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid ttl must not store a session, count=%d err=%v", count, err)
	}
}

func TestCreateSessionRejectsBlankIP(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	kept, err := st.CreateSession(ctx, "127.0.0.1", "kept", time.Hour)
	if err != nil || kept == "" {
		t.Fatal(err)
	}
	for _, ip := range []string{"", "   ", "127.0.0.\n1"} {
		token, err := st.CreateSession(ctx, ip, "blank", time.Hour)
		if token != "" || err == nil || !strings.Contains(err.Error(), "ip is invalid") {
			t.Fatalf("create ip=%q token=%q err=%v", ip, token, err)
		}
		token, err = st.CreateExclusiveSession(ctx, ip, "blank", time.Hour)
		if token != "" || err == nil || !strings.Contains(err.Error(), "ip is invalid") {
			t.Fatalf("exclusive ip=%q token=%q err=%v", ip, token, err)
		}
	}
	valid, err := st.ValidateSession(ctx, kept)
	if err != nil || !valid {
		t.Fatalf("blank ip must not replace the existing session, valid=%v err=%v", valid, err)
	}
	var count int
	if err = st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("sessions=%d err=%v", count, err)
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

func TestCreateSessionRejectsBrokenUserAgent(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	kept, err := st.CreateSession(ctx, "127.0.0.1", "kept", time.Hour)
	if err != nil || kept == "" {
		t.Fatal(err)
	}
	for _, ua := range []string{"ok\ninjected", "ok\rinjected", "ok\x00injected"} {
		token, err := st.CreateSession(ctx, "127.0.0.1", ua, time.Hour)
		if token != "" || err == nil || !strings.Contains(err.Error(), "user agent is invalid") {
			t.Fatalf("create ua=%q token=%q err=%v", ua, token, err)
		}
		token, err = st.CreateExclusiveSession(ctx, "127.0.0.1", ua, time.Hour)
		if token != "" || err == nil || !strings.Contains(err.Error(), "user agent is invalid") {
			t.Fatalf("exclusive ua=%q token=%q err=%v", ua, token, err)
		}
	}
	valid, err := st.ValidateSession(ctx, kept)
	if err != nil || !valid {
		t.Fatalf("broken user agent must not replace the existing session, valid=%v err=%v", valid, err)
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

func TestLoginFailureRejectsBlankIP(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err = st.RecordLoginFailure(ctx, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"", "   ", "127.0.0.\n1"} {
		if err = st.RecordLoginFailure(ctx, ip); err == nil || !strings.Contains(err.Error(), "ip is invalid") {
			t.Fatalf("record ip=%q err=%v", ip, err)
		}
		count, err := st.RecentLoginFailures(ctx, ip, time.Now().Add(-time.Minute))
		if err != nil || count != 0 {
			t.Fatalf("recent ip=%q count=%d err=%v", ip, count, err)
		}
		if err = st.ClearLoginFailures(ctx, ip); err != nil {
			t.Fatalf("clear ip=%q err=%v", ip, err)
		}
	}
	count, err := st.RecentLoginFailures(ctx, "127.0.0.1", time.Now().Add(-time.Minute))
	if err != nil || count != 1 {
		t.Fatalf("real ip failures = %d err=%v", count, err)
	}
	var stored int
	if err = st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM login_attempts`).Scan(&stored); err != nil || stored != 1 {
		t.Fatalf("stored attempts=%d err=%v", stored, err)
	}
}

func TestRecentLoginFailuresRejectsInvalidWindow(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err = st.RecordLoginFailure(ctx, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, since := range []time.Time{{}, time.Unix(0, 0).UTC(), time.Unix(-1, 0).UTC()} {
		count, err := st.RecentLoginFailures(ctx, "127.0.0.1", since)
		if count != 0 || err == nil || !strings.Contains(err.Error(), "login window is invalid") {
			t.Fatalf("since=%v count=%d err=%v", since, count, err)
		}
	}
	count, err := st.RecentLoginFailures(ctx, "127.0.0.1", time.Now().Add(-time.Minute))
	if err != nil || count != 1 {
		t.Fatalf("valid window count=%d err=%v", count, err)
	}
}

func TestSessionExpiry(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	token, err := st.CreateSession(context.Background(), "127.0.0.1", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(context.Background(), `UPDATE sessions SET expires_at=unixepoch()-1`); err != nil {
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
	expired, err := st.CreateSession(ctx, "127.0.0.1", "expired", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	live, err := st.CreateSession(ctx, "127.0.0.1", "live", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE sessions SET expires_at=unixepoch()-1 WHERE user_agent='expired'`); err != nil {
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
	if err = st.SetBillingCache(ctx, 1, "instance_bill", "2026-09", map[string]float64{"total": 1}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing account err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status,max_traffic) VALUES(1,'LTAItest','cn-hongkong','i-test','china','Unknown',200)`); err != nil {
		t.Fatal(err)
	}
	if err = st.SetBillingCache(ctx, 1, "instance_bill", "2026-09", map[string]float64{"total": 1}); err != nil {
		t.Fatal(err)
	}
}

func TestBillingCacheRejectsOversizedStoredPayload(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	insertTestAccount(t, st, 1)
	blob := strings.Repeat("m", maxBillingCacheBytes+1)
	if _, err = st.db.ExecContext(ctx, `INSERT INTO billing_cache(account_id,cache_type,billing_cycle,data,updated_at) VALUES(1,'balance','',?,unixepoch())`, blob); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_, err = st.BillingCache(ctx, 1, "balance", "", time.Hour, &got)
	if err == nil || !strings.Contains(err.Error(), "payload is too long") {
		t.Fatalf("err=%v", err)
	}
}

func TestBillingCacheRejectsInvalidPayload(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	insertTestAccount(t, st, 1)
	if _, err = st.db.ExecContext(ctx, `INSERT INTO billing_cache(account_id,cache_type,billing_cycle,data,updated_at) VALUES(1,'balance','','{',unixepoch())`); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	ok, err := st.BillingCache(ctx, 1, "balance", "", time.Hour, &got)
	if ok || err == nil || !strings.Contains(err.Error(), "payload is invalid") {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestBillingCacheRejectsInvalidTimestamp(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	insertTestAccount(t, st, 1)
	if _, err = st.db.ExecContext(ctx, `INSERT INTO billing_cache(account_id,cache_type,billing_cycle,data,updated_at) VALUES(1,'balance','','{"amount":1}',0)`); err != nil {
		t.Fatal(err)
	}
	var got map[string]float64
	ok, err := st.BillingCache(ctx, 1, "balance", "", time.Hour, &got)
	if ok || err == nil || !strings.Contains(err.Error(), "billing cache timestamp is invalid") {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestBillingCacheIsIsolatedPerAccount(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status,max_traffic) VALUES(1,'LTAIone','cn-hongkong','i-one','china','Unknown',200),(2,'LTAItwo','cn-hongkong','i-two','china','Unknown',200)`); err != nil {
		t.Fatal(err)
	}
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
	ok, err = st.BillingCache(ctx, 3, "balance", "", time.Hour, &got)
	if ok || !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing account cache ok=%v err=%v", ok, err)
	}
}

func TestBillingCacheExpiresByMaxAge(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status,max_traffic) VALUES(1,'LTAItest','cn-hongkong','i-test','china','Unknown',200)`); err != nil {
		t.Fatal(err)
	}
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

func TestSetBillingCacheRequiresActiveAccount(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err = st.SetBillingCache(ctx, 1, "balance", "", map[string]float64{"amount": 1}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing account err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status,max_traffic,deleted_at) VALUES(1,'LTAItest','cn-hongkong','i-test','china','Unknown',200,unixepoch())`); err != nil {
		t.Fatal(err)
	}
	if err = st.SetBillingCache(ctx, 1, "balance", "", map[string]float64{"amount": 1}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted account err=%v", err)
	}
	var count int
	if err = st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM billing_cache`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("inactive account must not store cache, count=%d err=%v", count, err)
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
	for _, name := range []string{"bad\nname", "bad\rname", "bad\x00name"} {
		if _, _, err = st.CreateAPIKey(ctx, name, []string{"widget:read"}, nil); err == nil || !strings.Contains(err.Error(), "api key name is invalid") {
			t.Fatalf("name=%q err=%v", name, err)
		}
	}
	keys, err := st.ListAPIKeys(ctx)
	if err != nil || len(keys) != 0 {
		t.Fatalf("broken names must not persist, keys=%#v err=%v", keys, err)
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

func TestAuthTokensRejectOversizedValues(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	long := strings.Repeat("a", maxAuthTokenBytes+1)
	valid, err := st.ValidateSession(ctx, long)
	if err != nil || valid {
		t.Fatalf("session valid=%v err=%v", valid, err)
	}
	if _, err = st.ValidateAPIKey(ctx, long); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("api key err=%v", err)
	}
	if err = st.DeleteSession(ctx, long); err != nil {
		t.Fatal(err)
	}
	token, err := st.CreateSession(ctx, "127.0.0.1", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	valid, err = st.ValidateSession(ctx, token)
	if err != nil || !valid {
		t.Fatalf("normal session valid=%v err=%v", valid, err)
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

func TestValidateAPIKeyDeduplicatesScopes(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	token := "cdt_duplicate_scopes_token"
	if _, err = st.db.ExecContext(ctx, `INSERT INTO api_keys(name,token_hash,scopes,created_at) VALUES('dup',?,'["widget:read","widget:read"]',unixepoch())`, security.TokenHash(token)); err != nil {
		t.Fatal(err)
	}
	scopes, err := st.ValidateAPIKey(ctx, token)
	if err != nil || len(scopes) != 1 || scopes[0] != "widget:read" {
		t.Fatalf("scopes=%v err=%v", scopes, err)
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
	now := time.Now().UTC()
	sameSecond := now.Add(time.Millisecond)
	if sameSecond.Unix() != now.Unix() {
		sameSecond = time.Unix(now.Unix(), int64(time.Second)-1).UTC()
	}
	if sameSecond.After(now) {
		if _, _, err = st.CreateAPIKey(context.Background(), "same-second", []string{"widget:read"}, &sameSecond); err == nil || !strings.Contains(err.Error(), "expiry must be in the future") {
			t.Fatalf("same-second expiry err=%v", err)
		}
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

func TestRevokeAndDeleteRejectNonPositiveID(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err = st.RevokeAPIKey(ctx, 0); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("revoke err=%v", err)
	}
	if err = st.RevokeAPIKey(ctx, 1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing revoke err=%v", err)
	}
	if err = st.DeletePasskey(ctx, 0); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("delete passkey err=%v", err)
	}
	if err = st.DeletePasskey(ctx, 1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing delete err=%v", err)
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

func TestValidateAPIKeyRejectsEmptyScopes(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	token := "cdt_empty_scopes_token"
	if _, err = st.db.ExecContext(ctx, `INSERT INTO api_keys(name,token_hash,scopes,created_at) VALUES('empty',?,'["widget:read",""]',unixepoch())`, security.TokenHash(token)); err != nil {
		t.Fatal(err)
	}
	if _, err = st.ValidateAPIKey(ctx, token); err == nil || !strings.Contains(err.Error(), "invalid API key scope") {
		t.Fatalf("mixed empty scope err=%v", err)
	}
	var lastUsed sql.NullInt64
	if err = st.db.QueryRowContext(ctx, `SELECT last_used_at FROM api_keys`).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if lastUsed.Valid {
		t.Fatal("empty scope must not record last_used_at")
	}
	if _, err = st.db.ExecContext(ctx, `UPDATE api_keys SET scopes='[]',last_used_at=NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.ValidateAPIKey(ctx, token); err == nil || !strings.Contains(err.Error(), "invalid API key scope") {
		t.Fatalf("empty scope list err=%v", err)
	}
	if err = st.db.QueryRowContext(ctx, `SELECT last_used_at FROM api_keys`).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if lastUsed.Valid {
		t.Fatal("empty scope list must not record last_used_at")
	}
}

func TestValidateAPIKeyRejectsPaddedScopes(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	token := "cdt_padded_scopes_token"
	if _, err = st.db.ExecContext(ctx, `INSERT INTO api_keys(name,token_hash,scopes,created_at) VALUES('pad',?,'["widget:read"," widget:read"]',unixepoch())`, security.TokenHash(token)); err != nil {
		t.Fatal(err)
	}
	if _, err = st.ValidateAPIKey(ctx, token); err == nil || !strings.Contains(err.Error(), "invalid API key scope") {
		t.Fatalf("padded scope err=%v", err)
	}
	var lastUsed sql.NullInt64
	if err = st.db.QueryRowContext(ctx, `SELECT last_used_at FROM api_keys`).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if lastUsed.Valid {
		t.Fatal("padded scope must not record last_used_at")
	}
}

func TestValidateAPIKeyRejectsOversizedScopesJSON(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	token := "cdt_oversized_scopes_token"
	blob := `["` + strings.Repeat("x", maxAPIKeyScopesJSONBytes) + `"]`
	if _, err = st.db.Exec(`INSERT INTO api_keys(name,token_hash,scopes,created_at) VALUES('huge',?,?,unixepoch())`, security.TokenHash(token), blob); err != nil {
		t.Fatal(err)
	}
	if _, err = st.ValidateAPIKey(ctx, token); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("validate err=%v", err)
	}
	if _, err = st.ListAPIKeys(ctx); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("list err=%v", err)
	}
	var lastUsed sql.NullInt64
	if err = st.db.QueryRow(`SELECT last_used_at FROM api_keys`).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if lastUsed.Valid {
		t.Fatal("oversized scopes must not record last_used_at")
	}
}

func TestListPasskeysRejectsInvalidTimestamp(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO passkeys(name,credential_id,credential_json,created_at) VALUES('zero',?,?,0)`, []byte("id"), `{"id":"x"}`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListPasskeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "passkey timestamp is invalid") {
		t.Fatalf("err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `DELETE FROM passkeys`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO passkeys(name,credential_id,credential_json,created_at,last_used_at) VALUES('used',?,?,unixepoch(),-1)`, []byte("id"), `{"id":"x"}`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListPasskeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "passkey timestamp is invalid") {
		t.Fatalf("last_used_at err=%v", err)
	}
}

func TestListPasskeysRejectsNonPositiveID(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO passkeys(id,name,credential_id,credential_json,created_at) VALUES(0,'zero',?,?,unixepoch())`, []byte("id"), `{"id":"x"}`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListPasskeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "passkey id is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestListPasskeysRejectsInvalidName(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO passkeys(name,credential_id,credential_json,created_at) VALUES('   ',?,?,unixepoch())`, []byte("id-blank"), `{"id":"x"}`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListPasskeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "passkey name is invalid") {
		t.Fatalf("blank name err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `DELETE FROM passkeys`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO passkeys(name,credential_id,credential_json,created_at) VALUES(?,?,?,unixepoch())`, strings.Repeat("n", maxPasskeyNameRunes+1), []byte("id-long"), `{"id":"x"}`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListPasskeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "passkey name is invalid") {
		t.Fatalf("long name err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `DELETE FROM passkeys`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO passkeys(name,credential_id,credential_json,created_at) VALUES(?,?,?,unixepoch())`, "bad\nname", []byte("id-break"), `{"id":"x"}`); err != nil {
		t.Fatal(err)
	}
	_, err = st.ListPasskeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "passkey name is invalid") {
		t.Fatalf("broken name err=%v", err)
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
	if err = st.SavePasskey(ctx, "no-key", webauthn.Credential{ID: []byte("credential-id")}); err == nil || !strings.Contains(err.Error(), "credential is invalid") {
		t.Fatalf("missing public key err=%v", err)
	}
	hugeID := webauthn.Credential{ID: []byte(strings.Repeat("i", maxPasskeyCredentialBytes+1)), PublicKey: []byte("public-key")}
	if err = st.SavePasskey(ctx, "huge-id", hugeID); err == nil || !strings.Contains(err.Error(), "credential is invalid") {
		t.Fatalf("oversized id err=%v", err)
	}
	hugeKey := webauthn.Credential{ID: []byte("credential-id"), PublicKey: []byte(strings.Repeat("k", maxPasskeyCredentialBytes+1))}
	if err = st.SavePasskey(ctx, "huge-key", hugeKey); err == nil || !strings.Contains(err.Error(), "credential is invalid") {
		t.Fatalf("oversized public key err=%v", err)
	}
	huge := webauthn.Credential{ID: []byte("credential-id"), PublicKey: []byte("public-key"), AttestationType: strings.Repeat("a", maxPasskeyJSONBytes)}
	if err = st.SavePasskey(ctx, "huge", huge); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("json err=%v", err)
	}
	items, err := st.ListPasskeys(ctx)
	if err != nil || len(items) != 0 {
		t.Fatalf("rejected passkeys=%#v err=%v", items, err)
	}
}

func TestLoadPasskeyCredentialsRejectsOversizedJSON(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	blob := strings.Repeat("k", maxPasskeyJSONBytes+1)
	if _, err = st.db.ExecContext(ctx, `INSERT INTO passkeys(name,credential_id,credential_json,created_at) VALUES(?,?,?,unixepoch())`, "poison", []byte("id"), blob); err != nil {
		t.Fatal(err)
	}
	_, err = st.LoadPasskeyCredentials(ctx)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadPasskeyCredentialsRejectsEmptyID(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO passkeys(name,credential_id,credential_json,created_at) VALUES('poison',?,'{}',unixepoch())`, []byte("id")); err != nil {
		t.Fatal(err)
	}
	_, err = st.LoadPasskeyCredentials(ctx)
	if err == nil || !strings.Contains(err.Error(), "credential is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadPasskeyCredentialsRejectsEmptyPublicKey(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	raw, err := json.Marshal(webauthn.Credential{ID: []byte("credential-id")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO passkeys(name,credential_id,credential_json,created_at) VALUES('poison',?,?,unixepoch())`, []byte("credential-id"), string(raw)); err != nil {
		t.Fatal(err)
	}
	_, err = st.LoadPasskeyCredentials(ctx)
	if err == nil || !strings.Contains(err.Error(), "credential is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadPasskeyCredentialsRejectsCredentialIDMismatch(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	raw, err := json.Marshal(webauthn.Credential{ID: []byte("credential-id"), PublicKey: []byte("public-key")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO passkeys(name,credential_id,credential_json,created_at) VALUES('poison',?,?,unixepoch())`, []byte("other-id"), string(raw)); err != nil {
		t.Fatal(err)
	}
	_, err = st.LoadPasskeyCredentials(ctx)
	if err == nil || !strings.Contains(err.Error(), "credential is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadPasskeyCredentialsRejectsOversizedID(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	id := []byte(strings.Repeat("i", maxPasskeyCredentialBytes+1))
	raw, err := json.Marshal(webauthn.Credential{ID: id, PublicKey: []byte("public-key")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO passkeys(name,credential_id,credential_json,created_at) VALUES('poison',?,?,unixepoch())`, id, string(raw)); err != nil {
		t.Fatal(err)
	}
	_, err = st.LoadPasskeyCredentials(ctx)
	if err == nil || !strings.Contains(err.Error(), "credential is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadPasskeyCredentialsRejectsOversizedPublicKey(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	id := []byte("credential-id")
	raw, err := json.Marshal(webauthn.Credential{ID: id, PublicKey: []byte(strings.Repeat("k", maxPasskeyCredentialBytes+1))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO passkeys(name,credential_id,credential_json,created_at) VALUES('poison',?,?,unixepoch())`, id, string(raw)); err != nil {
		t.Fatal(err)
	}
	_, err = st.LoadPasskeyCredentials(ctx)
	if err == nil || !strings.Contains(err.Error(), "credential is invalid") {
		t.Fatalf("err=%v", err)
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
	if err = st.SavePasskey(ctx, "bad\nname", credential); err == nil || !strings.Contains(err.Error(), "passkey name is invalid") {
		t.Fatalf("broken name err=%v", err)
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

func TestUpdatePasskeyCredentialRequiresMatchingRow(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	missing := webauthn.Credential{ID: []byte("missing-credential"), PublicKey: []byte("public-key")}
	if err = st.UpdatePasskeyCredential(ctx, missing); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing credential err=%v", err)
	}
	var count int
	if err = st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM passkeys`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("missing update must not insert, count=%d err=%v", count, err)
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
	insertTestAccount(t, first, 1)
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
	if err = st.AddOutbox(ctx, event, []string{"email", "email"}); err == nil || !strings.Contains(err.Error(), "channel is invalid") {
		t.Fatalf("duplicate channel err=%v", err)
	}
	if err = st.AddOutbox(ctx, domain.NotificationEvent{ID: "", Type: "threshold"}, []string{"email"}); err == nil || !strings.Contains(err.Error(), "event id is invalid") {
		t.Fatalf("empty id err=%v", err)
	}
	if err = st.AddOutbox(ctx, domain.NotificationEvent{ID: "   ", Type: "threshold"}, []string{"email"}); err == nil || !strings.Contains(err.Error(), "event id is invalid") {
		t.Fatalf("blank id err=%v", err)
	}
	if err = st.AddOutbox(ctx, domain.NotificationEvent{ID: " evt-1", Type: "threshold"}, []string{"email"}); err == nil || !strings.Contains(err.Error(), "event id is invalid") {
		t.Fatalf("padded id err=%v", err)
	}
	if err = st.AddOutbox(ctx, domain.NotificationEvent{ID: "evt\n1", Type: "threshold"}, []string{"email"}); err == nil || !strings.Contains(err.Error(), "event id is invalid") {
		t.Fatalf("broken id err=%v", err)
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
	event.Title = "bad\ntitle"
	if err = st.AddOutbox(ctx, event, []string{"email"}); err == nil || !strings.Contains(err.Error(), "event is invalid") {
		t.Fatalf("broken title err=%v", err)
	}
	event.Title = "t"
	event.Summary = "bad\nsum"
	if err = st.AddOutbox(ctx, event, []string{"email"}); err == nil || !strings.Contains(err.Error(), "event is invalid") {
		t.Fatalf("broken summary err=%v", err)
	}
	event.Summary = "s"
	event.Fields = map[string]string{strings.Repeat("k", maxNotificationFieldRunes+1): "v"}
	if err = st.AddOutbox(ctx, event, []string{"email"}); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("field err=%v", err)
	}
	event.Fields = map[string]string{"": "v"}
	if err = st.AddOutbox(ctx, event, []string{"email"}); err == nil || !strings.Contains(err.Error(), "field is invalid") {
		t.Fatalf("empty field err=%v", err)
	}
	event.Fields = map[string]string{" k": "v"}
	if err = st.AddOutbox(ctx, event, []string{"email"}); err == nil || !strings.Contains(err.Error(), "field is invalid") {
		t.Fatalf("padded field err=%v", err)
	}
	event.Fields = map[string]string{"k": "bad\nv"}
	if err = st.AddOutbox(ctx, event, []string{"email"}); err == nil || !strings.Contains(err.Error(), "field is invalid") {
		t.Fatalf("broken field value err=%v", err)
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

func TestClaimOutboxFailsOversizedPayload(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	blob := strings.Repeat("x", maxOutboxPayloadRunes+1)
	if _, err = st.db.ExecContext(ctx, `INSERT INTO notification_outbox(id,event_id,channel,payload,status,available_at,created_at,updated_at) VALUES(?,?,?,?,'queued',unixepoch(),unixepoch(),unixepoch())`, "evt-huge:webhook", "evt-huge", "webhook", blob); err != nil {
		t.Fatal(err)
	}
	_, err = st.ClaimOutbox(ctx)
	if err == nil || !strings.Contains(err.Error(), "payload is too long") {
		t.Fatalf("err=%v", err)
	}
	var status, lastError string
	if err = st.db.QueryRowContext(ctx, `SELECT status,last_error FROM notification_outbox WHERE event_id='evt-huge'`).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(lastError, "payload is too long") {
		t.Fatalf("status=%q last_error=%q", status, lastError)
	}
}

func TestClaimOutboxFailsInvalidStoredItem(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	cases := []struct {
		id      string
		channel string
		payload string
		err     string
	}{
		{id: "evt-sms:sms", channel: "sms", payload: `{"id":"evt-sms","type":"threshold","title":"t","summary":"s"}`, err: "channel is invalid"},
		{id: "evt-badjson:email", channel: "email", payload: "{", err: "payload is invalid"},
		{id: "evt-type:email", channel: "email", payload: `{"id":"evt-type","type":"unknown","title":"t","summary":"s"}`, err: "event type is invalid"},
		{id: "evt-pad:email", channel: "email", payload: `{"id":" evt-pad","type":"threshold","title":"t","summary":"s"}`, err: "event id is invalid"},
		{id: " evt-row:email", channel: "email", payload: `{"id":"evt-row","type":"threshold","title":"t","summary":"s"}`, err: "event id is invalid"},
		{id: "evt\nbreak:email", channel: "email", payload: `{"id":"evt-break","type":"threshold","title":"t","summary":"s"}`, err: "event id is invalid"},
		{id: "evt-title:email", channel: "email", payload: `{"id":"evt-title","type":"threshold","title":"t\nn","summary":"s"}`, err: "event is invalid"},
	}
	for _, tc := range cases {
		if _, err = st.db.ExecContext(ctx, `INSERT INTO notification_outbox(id,event_id,channel,payload,status,available_at,created_at,updated_at) VALUES(?,?,?,?,'queued',unixepoch(),unixepoch(),unixepoch())`, tc.id, strings.Split(tc.id, ":")[0], tc.channel, tc.payload); err != nil {
			t.Fatal(err)
		}
		_, err = st.ClaimOutbox(ctx)
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Fatalf("%s err=%v", tc.id, err)
		}
		var status, lastError string
		if err = st.db.QueryRowContext(ctx, `SELECT status,last_error FROM notification_outbox WHERE id=?`, tc.id).Scan(&status, &lastError); err != nil {
			t.Fatal(err)
		}
		if status != "failed" || !strings.Contains(lastError, tc.err) {
			t.Fatalf("%s status=%q last_error=%q", tc.id, status, lastError)
		}
	}
	if _, err = st.ClaimOutbox(ctx); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("poisoned rows must not stay queued: err=%v", err)
	}
}

func TestValidateOutboxItem(t *testing.T) {
	event := domain.NotificationEvent{ID: "evt-1", Type: "threshold", Title: "t", Summary: "s"}
	if err := ValidateOutboxItem("webhook", event); err != nil {
		t.Fatalf("valid item err=%v", err)
	}
	if err := ValidateOutboxItem("sms", event); err == nil || !strings.Contains(err.Error(), "channel is invalid") {
		t.Fatalf("channel err=%v", err)
	}
	if err := ValidateOutboxItem("email", domain.NotificationEvent{ID: "", Type: "threshold"}); err == nil || !strings.Contains(err.Error(), "event id is invalid") {
		t.Fatalf("empty id err=%v", err)
	}
	if err := ValidateOutboxItem("email", domain.NotificationEvent{ID: " evt-1", Type: "threshold"}); err == nil || !strings.Contains(err.Error(), "event id is invalid") {
		t.Fatalf("padded id err=%v", err)
	}
	if err := ValidateOutboxItem("email", domain.NotificationEvent{ID: "evt\n1", Type: "threshold"}); err == nil || !strings.Contains(err.Error(), "event id is invalid") {
		t.Fatalf("broken id err=%v", err)
	}
	event.Title = strings.Repeat("t", maxNotificationTitleRunes+1)
	if err := ValidateOutboxItem("email", event); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("title err=%v", err)
	}
	event.Title = "t"
	event.Summary = "bad\nsum"
	if err := ValidateOutboxItem("email", event); err == nil || !strings.Contains(err.Error(), "event is invalid") {
		t.Fatalf("broken summary err=%v", err)
	}
	event.Summary = "s"
	event.Fields = map[string]string{" k": "v"}
	if err := ValidateOutboxItem("email", event); err == nil || !strings.Contains(err.Error(), "field is invalid") {
		t.Fatalf("padded field err=%v", err)
	}
	event.Fields = map[string]string{"k": "bad\nv"}
	if err := ValidateOutboxItem("email", event); err == nil || !strings.Contains(err.Error(), "field is invalid") {
		t.Fatalf("broken field value err=%v", err)
	}
}

func TestOutboxCompleteAndFailRejectOversizedIDs(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	long := strings.Repeat("o", maxOutboxIDBytes+1)
	if err = st.CompleteOutbox(ctx, ""); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("empty complete err=%v", err)
	}
	if err = st.CompleteOutbox(ctx, " evt-1:email"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("padded complete err=%v", err)
	}
	if err = st.FailOutbox(ctx, OutboxItem{ID: " evt-1:email"}, errors.New("boom")); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("padded fail err=%v", err)
	}
	if err = st.CompleteOutbox(ctx, "evt\n1:email"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("broken complete err=%v", err)
	}
	if err = st.FailOutbox(ctx, OutboxItem{ID: "evt\n1:email"}, errors.New("boom")); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("broken fail err=%v", err)
	}
	if err = st.CompleteOutbox(ctx, long); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("oversized complete err=%v", err)
	}
	if err = st.FailOutbox(ctx, OutboxItem{ID: long}, errors.New("boom")); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("oversized fail err=%v", err)
	}
	if err = st.FailOutbox(ctx, OutboxItem{ID: "evt-1:email"}, nil); err == nil || !strings.Contains(err.Error(), "outbox error is required") {
		t.Fatalf("nil error err=%v", err)
	}
	if err = st.FailOutbox(ctx, OutboxItem{ID: "evt-1:email", Attempts: -1, MaxAttempts: 5}, errors.New("boom")); err == nil || !strings.Contains(err.Error(), "outbox attempts are invalid") {
		t.Fatalf("negative attempts err=%v", err)
	}
	if err = st.FailOutbox(ctx, OutboxItem{ID: "missing:email", Attempts: 1, MaxAttempts: 5}, errors.New("boom")); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing fail err=%v", err)
	}
	if err = st.CompleteOutbox(ctx, "missing:email"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing complete err=%v", err)
	}
}

func TestClaimOutboxFailsInvalidAttempts(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	payload := `{"id":"evt-attempts","type":"threshold","title":"t","summary":"s"}`
	if _, err = st.db.ExecContext(ctx, `INSERT INTO notification_outbox(id,event_id,channel,payload,status,attempts,max_attempts,available_at,created_at,updated_at) VALUES('evt-attempts:email','evt-attempts','email',?,'queued',0,0,unixepoch(),unixepoch(),unixepoch())`, payload); err != nil {
		t.Fatal(err)
	}
	_, err = st.ClaimOutbox(ctx)
	if err == nil || !strings.Contains(err.Error(), "outbox attempts are invalid") {
		t.Fatalf("err=%v", err)
	}
	var status, lastError string
	if err = st.db.QueryRowContext(ctx, `SELECT status,last_error FROM notification_outbox WHERE id='evt-attempts:email'`).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(lastError, "outbox attempts are invalid") {
		t.Fatalf("status=%q last_error=%q", status, lastError)
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
	if err = st.AddTrafficStats(ctx, 1, 0, now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing account err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status,max_traffic) VALUES(1,'LTAItest','cn-hongkong','i-test','china','Unknown',200)`); err != nil {
		t.Fatal(err)
	}
	if err = st.AddTrafficStats(ctx, 1, 0, now); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{time.Time{}, time.Unix(0, 0).UTC(), time.Unix(-1, 0).UTC()} {
		if err = st.AddTrafficStats(ctx, 1, 1, at); err == nil || !strings.Contains(err.Error(), "traffic timestamp is invalid") {
			t.Fatalf("at=%v err=%v", at, err)
		}
	}
	var count int
	if err = st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM traffic_hourly`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("invalid traffic timestamp must not insert, count=%d err=%v", count, err)
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
	if err = st.UpdateRuntime(ctx, 1, 1, domain.StatusRunning, now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing account err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status,max_traffic) VALUES(1,'LTAItest','cn-hongkong','i-test','china','Unknown',200)`); err != nil {
		t.Fatal(err)
	}
	if err = st.UpdateRuntime(ctx, 1, 1, domain.StatusRunning, now); err != nil {
		t.Fatal(err)
	}
	if err = st.UpdateRuntime(ctx, 1, 1, "Pending", now); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRuntimeRejectsInvalidTimestamp(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status,max_traffic) VALUES(1,'LTAItest','cn-hongkong','i-test','china','Unknown',200)`); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{time.Time{}, time.Unix(0, 0).UTC(), time.Unix(-1, 0).UTC()} {
		if err = st.UpdateRuntime(ctx, 1, 1, domain.StatusRunning, at); err == nil || !strings.Contains(err.Error(), "runtime timestamp is invalid") {
			t.Fatalf("runtime at=%v err=%v", at, err)
		}
		if err = st.UpdateKeepAliveAt(ctx, 1, at); err == nil || !strings.Contains(err.Error(), "keepalive timestamp is invalid") {
			t.Fatalf("keepalive at=%v err=%v", at, err)
		}
	}
	var updated, keepAlive int64
	if err = st.db.QueryRowContext(ctx, `SELECT updated_at,last_keep_alive_at FROM accounts WHERE id=1`).Scan(&updated, &keepAlive); err != nil {
		t.Fatal(err)
	}
	if updated != 0 || keepAlive != 0 {
		t.Fatalf("invalid timestamps must not persist, updated=%d keepalive=%d", updated, keepAlive)
	}
}

func TestUpdateKeepAliveAtRequiresActiveAccount(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	if err = st.UpdateKeepAliveAt(ctx, 1, now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing account err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status,max_traffic,deleted_at) VALUES(1,'LTAItest','cn-hongkong','i-test','china','Unknown',200,unixepoch())`); err != nil {
		t.Fatal(err)
	}
	if err = st.UpdateKeepAliveAt(ctx, 1, now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted account err=%v", err)
	}
	if err = st.UpdateRuntime(ctx, 1, 1, domain.StatusRunning, now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted runtime err=%v", err)
	}
}

func TestTrafficStatsUpsertAndHistoryOrder(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err = st.History(ctx, 1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing account history err=%v", err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status,max_traffic) VALUES(1,'LTAIone','cn-hongkong','i-one','china','Unknown',200)`); err != nil {
		t.Fatal(err)
	}
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
	if _, err = st.db.ExecContext(ctx, `INSERT INTO accounts(id,access_key_id,region_id,instance_id,site_type,instance_status,max_traffic) VALUES(1,'LTAIone','cn-hongkong','i-one','china','Unknown',200),(2,'LTAItwo','cn-hongkong','i-two','china','Unknown',200)`); err != nil {
		t.Fatal(err)
	}
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
	if _, err = st.History(ctx, 3); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing account history err=%v", err)
	}
	if err = st.AddTrafficStats(ctx, 3, 33, now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing account stats err=%v", err)
	}
}

func TestHistoryRejectsInvalidTrafficSamples(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	insertTestAccount(t, st, 1)
	if _, err = st.db.ExecContext(ctx, `INSERT INTO traffic_hourly(account_id,traffic,recorded_at) VALUES(1,-1,unixepoch())`); err != nil {
		t.Fatal(err)
	}
	_, err = st.History(ctx, 1)
	if err == nil || !strings.Contains(err.Error(), "traffic sample is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestHistoryRejectsInvalidTimestamp(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	insertTestAccount(t, st, 1)
	if _, err = st.db.ExecContext(ctx, `INSERT INTO traffic_hourly(account_id,traffic,recorded_at) VALUES(1,1.5,unixepoch())`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO traffic_daily(account_id,traffic,recorded_at) VALUES(1,1.5,0)`); err != nil {
		t.Fatal(err)
	}
	_, err = st.History(ctx, 1)
	if err == nil || !strings.Contains(err.Error(), "traffic timestamp is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestLastMonitorRunRejectsInvalidValue(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	got, err := st.LastMonitorRun(ctx)
	if err != nil || !got.IsZero() {
		t.Fatalf("missing run = %v err=%v", got, err)
	}
	if _, err = st.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES('last_monitor_run','not-a-unix')`); err != nil {
		t.Fatal(err)
	}
	_, err = st.LastMonitorRun(ctx)
	if err == nil || !strings.Contains(err.Error(), "last monitor run is invalid") {
		t.Fatalf("err=%v", err)
	}
}

func TestSetLastMonitorRunRejectsInvalidValue(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	for _, at := range []time.Time{time.Time{}, time.Unix(0, 0).UTC(), time.Unix(-1, 0).UTC()} {
		if err = st.SetLastMonitorRun(ctx, at); err == nil || !strings.Contains(err.Error(), "last monitor run is invalid") {
			t.Fatalf("at=%v err=%v", at, err)
		}
	}
	var stored string
	if err = st.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='last_monitor_run'`).Scan(&stored); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("invalid writes must not store last_monitor_run: stored=%q err=%v", stored, err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err = st.SetLastMonitorRun(ctx, now); err != nil {
		t.Fatal(err)
	}
	got, err := st.LastMonitorRun(ctx)
	if err != nil || !got.Equal(now) {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestOutboxRetriesThenExhausts(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	_, err = st.db.Exec(`INSERT INTO notification_outbox(id,event_id,channel,payload,status,attempts,max_attempts,available_at,last_error,created_at,updated_at) VALUES('out-1','evt-1','telegram','{"id":"evt-1","type":"threshold","title":"t","summary":"s"}','queued',0,2,unixepoch(),'',unixepoch(),unixepoch())`)
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
