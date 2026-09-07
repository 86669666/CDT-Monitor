package store

import (
	"context"
	"database/sql"
	"errors"
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
INSERT INTO settings(key,value) VALUES('admin_password','legacy-password'),('notify_tg_token','legacy-token'),('notify_wh_secret','legacy-webhook-secret');
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
	if err = st.db.QueryRow(`SELECT access_key_secret FROM accounts WHERE id=1`).Scan(&secret); err != nil {
		t.Fatal(err)
	}
	if !security.IsEncrypted(token) || !security.IsEncrypted(webhook) || !security.IsEncrypted(secret) {
		t.Fatal("legacy secrets were not encrypted")
	}
	telegram, err := st.Decrypt(token)
	if err != nil || telegram != "legacy-token" {
		t.Fatalf("telegram token = %q err=%v", telegram, err)
	}
	webhookPlain, err := st.Decrypt(webhook)
	if err != nil || webhookPlain != "legacy-webhook-secret" {
		t.Fatalf("webhook secret = %q err=%v", webhookPlain, err)
	}
	storedSecret, err := st.AccountSecret(context.Background(), 1)
	if err != nil || storedSecret != "legacy-secret" {
		t.Fatalf("account secret = %q err=%v", storedSecret, err)
	}
	valid, err := st.VerifyAdminPassword(context.Background(), "legacy-password")
	if err != nil || !valid {
		t.Fatalf("legacy password failed: %v", err)
	}
	var hash string
	_ = st.db.QueryRow(`SELECT value FROM settings WHERE key='admin_password'`).Scan(&hash)
	if hash == "legacy-password" {
		t.Fatal("legacy password was not upgraded")
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
