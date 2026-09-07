package engine

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/notify"
	"github.com/wang4386/CDT-Monitor/internal/store"
)

func TestRunOnceReportsBusyLease(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	first := New(st, nil, notify.New(), slog.Default(), 1)
	second := New(st, nil, notify.New(), slog.Default(), 1)
	if _, err = st.AcquireLease(context.Background(), "monitor", first.owner, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err = second.RunOnce(context.Background()); !errors.Is(err, ErrMonitorBusy) {
		t.Fatalf("expected busy lease, got %v", err)
	}
}

func TestRunOnceRenewsLeaseForSameOwner(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	eng := New(st, newFakeProvider(), notify.New(), slog.Default(), 1)
	if err = eng.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = eng.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRunOnceDeduplicatesMonitorJobsForTheSameMinute(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	eng := New(st, newFakeProvider(), notify.New(), slog.New(slog.NewTextHandler(io.Discard, nil)), 1)
	ctx := context.Background()
	if err := eng.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := eng.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	count, err := st.CountQueuedJobs(ctx)
	if err != nil || count != 1 {
		t.Fatalf("queued jobs = %d err=%v account=%d", count, err, account.ID)
	}
}

func TestRunOnceTakesExpiredLease(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	first := New(st, newFakeProvider(), notify.New(), slog.Default(), 1)
	second := New(st, newFakeProvider(), notify.New(), slog.Default(), 1)
	ctx := context.Background()
	if err = first.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB().ExecContext(ctx, `UPDATE scheduler_leases SET expires_at=unixepoch()-1 WHERE name='monitor'`); err != nil {
		t.Fatal(err)
	}
	if err = second.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
}

func setupAccount(t *testing.T, mutate func(*domain.Config)) (*store.Store, domain.Account) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	config := domain.Config{
		AdminPassword:    "Strong-Password-42!",
		TrafficThreshold: 95,
		ShutdownMode:     "KeepCharging",
		ThresholdAction:  "stop_and_notify",
		APIInterval:      600,
		Timezone:         "Asia/Shanghai",
		Accounts: []domain.Account{{
			AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china",
		}},
	}
	if mutate != nil {
		mutate(&config)
	}
	if err = st.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	accounts, err := st.ListAccounts(context.Background())
	if err != nil || len(accounts) != 1 {
		t.Fatalf("accounts=%v err=%v", accounts, err)
	}
	return st, accounts[0]
}
