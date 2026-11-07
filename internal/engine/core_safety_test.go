package engine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/notify"
	"github.com/wang4386/CDT-Monitor/internal/store"
)

type afterSendProvider struct {
	*fakeProvider
	failure string
}

func (p *afterSendProvider) ControlInstance(ctx context.Context, a domain.Account, secret, action, mode string) error {
	p.fakeProvider.ControlInstance(ctx, a, secret, action, mode)
	switch p.failure {
	case "panic":
		panic("test-only-after-remote-effect")
	case "timeout":
		return context.DeadlineExceeded
	}
	return nil
}

func TestCoreThresholdKnownBeforeSendRemainsEligible(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	ctx := t.Context()
	p := newFakeProvider()
	p.traffic = 200
	e := New(st, p, notify.New(), quietLogger(), 1)
	var original string
	st.DB().QueryRow(`SELECT access_key_secret FROM accounts WHERE id=?`, account.ID).Scan(&original)
	st.DB().Exec(`UPDATE accounts SET access_key_secret='' WHERE id=?`, account.ID)
	if _, err := e.processAccount(ctx, account.ID, true); err == nil {
		t.Fatal("missing secret must fail before send")
	}
	if len(p.controlActions()) != 0 {
		t.Fatal("known-before-send failure contacted provider")
	}
	var count int
	st.DB().QueryRow(`SELECT count(*) FROM action_events WHERE type='threshold_stop'`).Scan(&count)
	if count != 0 {
		t.Fatal("pre-send failure consumed threshold eligibility")
	}
	st.DB().Exec(`UPDATE accounts SET access_key_secret=? WHERE id=?`, original, account.ID)
	if _, err := e.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	if len(p.controlActions()) != 1 {
		t.Fatal("safe later attempt missing")
	}
}

func TestCoreUnknownThresholdNeverReplaysAndExactReadCanConfirm(t *testing.T) {
	for _, failure := range []string{"panic", "timeout", "persist"} {
		t.Run(failure, func(t *testing.T) {
			st, account := setupAccount(t, nil)
			defer st.Close()
			ctx := t.Context()
			p := &afterSendProvider{fakeProvider: newFakeProvider(), failure: failure}
			p.traffic = 200
			if failure == "persist" {
				_, err := st.DB().Exec(`CREATE TRIGGER fail_submitted BEFORE UPDATE OF status ON action_events WHEN NEW.status='submitted' BEGIN SELECT RAISE(FAIL,'test persistence failure'); END`)
				if err != nil {
					t.Fatal(err)
				}
			}
			e := New(st, p, notify.New(), quietLogger(), 2)
			job, err := e.Enqueue(ctx, JobRefreshAccount, account.ID, `{}`, "core:unknown")
			if err != nil {
				t.Fatal(err)
			}
			e.RunQueuedJobs(ctx)
			got, err := st.GetJob(ctx, job.ID)
			if err != nil || got.Status != "interrupted" {
				t.Fatalf("unknown operation not visible %+v %v", got, err)
			}
			var status, target string
			st.DB().QueryRow(`SELECT status,target FROM action_events WHERE type='threshold_stop'`).Scan(&status, &target)
			if status != "uncertain" && status != "attempting" {
				t.Fatalf("unknown action=%s", status)
			}
			if target != store.ActionTarget(account, "KeepCharging") {
				t.Fatal("target identity absent")
			}
			for _, observed := range []string{domain.StatusRunning, domain.StatusUnknown, domain.StatusStopping} {
				p.status = observed
				if _, err = e.processAccount(ctx, account.ID, true); err != nil {
					t.Fatal(err)
				}
				p.traffic = 1
				e.processAccount(ctx, account.ID, true)
				p.traffic = 200
				e.processAccount(ctx, account.ID, true)
				if len(p.controlActions()) != 1 {
					t.Fatal("unknown effect replayed after read or threshold reset")
				}
			}
			p.status = domain.StatusStopped
			p.statusErr = errors.New("status unavailable")
			e.processAccount(ctx, account.ID, true)
			st.DB().QueryRow(`SELECT status FROM action_events WHERE type='threshold_stop'`).Scan(&status)
			if status == "confirmed" {
				t.Fatal("failed read confirmed action")
			}
			p.statusErr = nil
			if _, err = e.processAccount(ctx, account.ID, true); err != nil {
				t.Fatal(err)
			}
			st.DB().QueryRow(`SELECT status FROM action_events WHERE type='threshold_stop'`).Scan(&status)
			if status != "confirmed" {
				t.Fatal("same-target stopped did not confirm")
			}
			blocked, _ := st.AutomationBlocked(ctx, account.ID, target)
			if !blocked {
				t.Fatal("unreviewed interrupted job silently released")
			}
			if err = e.ResolveRecovery(ctx, "job", job.ID, "verified original target stopped"); err != nil {
				t.Fatal(err)
			}
			blocked, _ = st.AutomationBlocked(ctx, account.ID, target)
			if blocked {
				t.Fatal("resolved records still block")
			}
			if len(p.controlActions()) != 1 {
				t.Fatal("review replayed payload")
			}
		})
	}
}

func TestCoreThresholdTargetDriftAndConcurrentWorkers(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	ctx := t.Context()
	p := newFakeProvider()
	p.traffic = 200
	e := New(st, p, notify.New(), quietLogger(), 3)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; e.processAccount(ctx, account.ID, true) }()
	}
	close(start)
	wg.Wait()
	if len(p.controlActions()) != 1 {
		t.Fatal("concurrent threshold calls duplicated")
	}
	p.status = domain.StatusStopped
	// Same numeric account ID now points at a different cloud instance.
	if _, err := st.DB().Exec(`UPDATE accounts SET instance_id='i-other' WHERE id=?`, account.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	var status string
	st.DB().QueryRow(`SELECT status FROM action_events WHERE type='threshold_stop'`).Scan(&status)
	if status == "confirmed" {
		t.Fatal("different instance confirmed original action")
	}
	p.traffic = 1
	e.processAccount(ctx, account.ID, true)
	p.traffic = 200
	p.status = domain.StatusRunning
	e.processAccount(ctx, account.ID, true)
	if len(p.controlActions()) != 1 {
		t.Fatal("target change or threshold crossing released unknown action")
	}
	summaries, _, err := e.Summary(ctx)
	if err != nil || !summaries[0].AutomationBlocked {
		t.Fatal("target drift block not visible")
	}
}

func TestCoreDailyReportWorkerRejectsDeletedAndMismatchedAccounts(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	ctx := t.Context()
	p := newFakeProvider()
	e := New(st, p, notify.New(), quietLogger(), 1)
	job, err := e.EnqueueDailyReportForAccount(ctx, true, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	st.DB().Exec(`UPDATE accounts SET deleted_at=unixepoch() WHERE id=?`, account.ID)
	if _, err = e.runJob(ctx, job); err == nil {
		t.Fatal("deleted report target executed")
	}
	job.Payload = `{"account_id":0,"force":true}`
	if _, err = e.runJob(ctx, job); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatal("account target silently became global")
	}
	var count int
	st.DB().QueryRow(`SELECT count(*) FROM notification_outbox`).Scan(&count)
	if count != 0 {
		t.Fatal("invalid report delivered notification")
	}
	if len(p.controlActions()) != 0 {
		t.Fatal("invalid report mutated cloud")
	}
}
