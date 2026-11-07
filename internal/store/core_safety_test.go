package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/runtimeowner"
)

func safetyConfig(label string) domain.Config {
	return domain.Config{AdminPassword: "Strong-Password-" + label, TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAI" + label, AccessKeySecret: "test-only-secret", RegionID: "cn-hongkong", InstanceID: "i-" + label, MaxTraffic: 200, SiteType: "china"}}}
}

func TestCoreSetupAtomicWinner(t *testing.T) {
	for _, handles := range []int{1, 2} {
		for _, empty := range []bool{false, true} {
			t.Run(fmt.Sprintf("handles%d-empty%v", handles, empty), func(t *testing.T) {
				dir := t.TempDir()
				first, err := Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer first.Close()
				second := first
				if handles == 2 {
					second, err = Open(dir)
					if err != nil {
						t.Fatal(err)
					}
					defer second.Close()
				}
				if empty {
					if _, err = first.db.Exec(`INSERT INTO settings(key,value) VALUES('admin_password','')`); err != nil {
						t.Fatal(err)
					}
				}
				configs := []domain.Config{safetyConfig("Alpha"), safetyConfig("Beta")}
				configs[1].TrafficThreshold = 72
				stores := []*Store{first, second}
				errs := make([]error, 2)
				start := make(chan struct{})
				var wg sync.WaitGroup
				for i := range stores {
					wg.Add(1)
					go func(i int) { defer wg.Done(); <-start; errs[i] = stores[i].Setup(context.Background(), configs[i]) }(i)
				}
				close(start)
				wg.Wait()
				winner := -1
				for i, e := range errs {
					if e == nil {
						if winner != -1 {
							t.Fatal("multiple initialization winners")
						}
						winner = i
					}
				}
				if winner == -1 {
					t.Fatalf("no winner: %v", errs)
				}
				got, err := first.GetConfig(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if len(got.Accounts) != 1 || got.Accounts[0].AccessKeyID != configs[winner].Accounts[0].AccessKeyID || got.TrafficThreshold != configs[winner].TrafficThreshold {
					t.Fatal("mixed winner config")
				}
				for i, c := range configs {
					ok, err := first.VerifyAdminPassword(t.Context(), c.AdminPassword)
					if err != nil || ok != (i == winner) {
						t.Fatalf("password winner mismatch: %d %v", i, err)
					}
				}
			})
		}
	}
}

func TestCoreSetupRollbackAndConfigAtomicity(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bad := safetyConfig("Bad")
	bad.Accounts[0].AccessKeySecret = ""
	if st.Setup(t.Context(), bad) == nil {
		t.Fatal("invalid setup succeeded")
	}
	initialized, _ := st.IsInitialized(t.Context())
	if initialized {
		t.Fatal("failed setup consumed eligibility")
	}
	good := safetyConfig("Good")
	if err = st.Setup(t.Context(), good); err != nil {
		t.Fatal(err)
	}
	var hashBefore string
	st.db.QueryRow(`SELECT value FROM settings WHERE key='admin_password'`).Scan(&hashBefore)
	base, err := st.GetConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	baseJSON, _ := json.Marshal(base)
	for _, mutate := range []func(*domain.Config){
		func(c *domain.Config) { c.AdminPassword = "New-password-123"; c.TrafficThreshold = 55 },
		func(c *domain.Config) { c.DailyReportTime = "24:00" },
		func(c *domain.Config) {
			c.Accounts = append(c.Accounts, domain.Account{AccessKeyID: "LTAIother", AccessKeySecret: "test", RegionID: "cn-shanghai", MaxTraffic: 200, DailyReportTime: "25:00"})
		},
		func(c *domain.Config) { c.Accounts[0].ShutdownMode = "invalid" },
	} {
		var c domain.Config
		json.Unmarshal(baseJSON, &c)
		mutate(&c)
		if st.SaveConfig(t.Context(), c) == nil {
			t.Fatal("invalid full config succeeded")
		}
		got, err := st.GetConfig(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(got)
		if string(b) != string(baseJSON) {
			t.Fatal("rejected config changed data")
		}
		var hash string
		st.db.QueryRow(`SELECT value FROM settings WHERE key='admin_password'`).Scan(&hash)
		if hash != hashBefore {
			t.Fatal("password hash changed")
		}
	}
	for _, clock := range []string{"", "00:00", "23:59", " 08\uff1a09 "} {
		c, err := st.GetConfig(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		c.DailyReportTime = clock
		c.Accounts[0].DailyReportTime = clock
		if err = st.SaveConfig(t.Context(), c); err != nil {
			t.Fatal(err)
		}
		got, err := st.GetConfig(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		want, _ := NormalizeDailyReportTime(clock, "22:00")
		if got.DailyReportTime != want {
			t.Fatal("global clock not normalized")
		}
		want, _ = NormalizeDailyReportTime(clock, "00:00")
		if got.Accounts[0].DailyReportTime != want {
			t.Fatal("account clock not normalized")
		}
		if err = st.UpdateAccountSettings(t.Context(), got.Accounts[0].ID, nil, "", false, "", "", nil, clock); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCoreOwnedRecoveryPreservesEvidenceAndKeys(t *testing.T) {
	dir := t.TempDir()
	owner, err := runtimeowner.Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.Setup(t.Context(), safetyConfig("Recovery")); err != nil {
		t.Fatal(err)
	}
	account, _ := st.GetAccount(t.Context(), 1)
	job, err := st.EnqueueJob(t.Context(), "refresh_account", 1, `{}`, "refresh:recovery", 3)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := st.ClaimJob(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != job.ID {
		t.Fatal("wrong claim")
	}
	_, err = st.db.Exec(`UPDATE jobs SET error='previous sanitized cause' WHERE id=?; INSERT INTO notification_outbox(id,event_id,channel,payload,status,attempts,max_attempts,available_at,last_error,created_at,updated_at) VALUES('unknown-outbox','evt','email','{}','sending',1,5,unixepoch(),'previous delivery cause',unixepoch(),unixepoch())`, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.RecordActionEvent(t.Context(), "threshold:1:stop", 1, "threshold_stop", "attempting", "legacy attempt"); err != nil {
		t.Fatal(err)
	}
	queued, err := st.EnqueueJob(t.Context(), "daily_report", 0, `{}`, "report:queued", 3)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	got, _ := other.GetJob(t.Context(), job.ID)
	if got.Status != "running" {
		t.Fatal("ordinary Open stole work")
	}
	if err = st.RecoverInterruptedWork(t.Context(), nil); err == nil {
		t.Fatal("unowned recovery allowed")
	}
	if err = st.RecoverInterruptedWork(t.Context(), owner); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetJob(t.Context(), job.ID)
	if err != nil || got.Status != "interrupted" || !strings.Contains(got.Error, "previous sanitized cause") || !strings.Contains(got.Error, "outcome_unknown") {
		t.Fatalf("bad recovered job: %+v %v", got, err)
	}
	same, err := st.EnqueueJob(t.Context(), "refresh_account", 1, `{}`, "refresh:recovery", 3)
	if err != nil || same.ID != job.ID {
		t.Fatal("unresolved dedupe key released")
	}
	stillQueued, _ := st.GetJob(t.Context(), queued.ID)
	if stillQueued.Status != "queued" {
		t.Fatal("queued work changed")
	}
	var status, detail, target string
	st.db.QueryRow(`SELECT status,last_error FROM notification_outbox WHERE id='unknown-outbox'`).Scan(&status, &detail)
	if status != "failed" || !strings.Contains(detail, "delivery_unknown") || !strings.Contains(detail, "previous delivery cause") {
		t.Fatal("notification evidence lost")
	}
	st.db.QueryRow(`SELECT status,target FROM action_events WHERE event_key='threshold:1:stop'`).Scan(&status, &target)
	if status != "uncertain" || target != "" {
		t.Fatal("legacy target guessed")
	}
	if err = st.ResolveRecovery(t.Context(), "job", job.ID, "checked original request in cloud console"); err != nil {
		t.Fatal(err)
	}
	blocked, err := st.AutomationBlocked(t.Context(), 1, ActionTarget(account, "KeepCharging"))
	if err != nil || !blocked {
		t.Fatal("resolving job also resolved action")
	}
	if err = st.ResolveRecovery(t.Context(), "action", "threshold:1:stop", "reviewed legacy target separately"); err != nil {
		t.Fatal(err)
	}
	blocked, err = st.AutomationBlocked(t.Context(), 1, ActionTarget(account, "KeepCharging"))
	if err != nil || blocked {
		t.Fatal("explicit review did not unblock")
	}
	var audits int
	st.db.QueryRow(`SELECT count(*) FROM logs WHERE type='audit' AND message LIKE 'Recovery reviewed%'`).Scan(&audits)
	if audits != 2 {
		t.Fatal("missing review audit")
	}
	got, _ = st.GetJob(t.Context(), job.ID)
	if got.Status != "interrupted" || got.Attempts != 1 {
		t.Fatal("review replayed or rewrote job history")
	}
}

func TestCoreDailyReportDeletedAccountCannotDeduplicate(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.Setup(t.Context(), safetyConfig("Daily")); err != nil {
		t.Fatal(err)
	}
	job, err := st.EnqueueJob(t.Context(), "daily_report", 1, `{"account_id":1}`, "daily:1", 3)
	if err != nil {
		t.Fatal(err)
	}
	st.db.Exec(`UPDATE accounts SET deleted_at=unixepoch() WHERE id=1`)
	if _, err = st.EnqueueJob(t.Context(), "daily_report", 1, `{"account_id":1}`, "daily:1", 3); err != sql.ErrNoRows {
		t.Fatalf("deleted account reused old job %v", err)
	}
	got, _ := st.GetJob(t.Context(), job.ID)
	if got.Status != "queued" {
		t.Fatal("test precondition")
	}
}
