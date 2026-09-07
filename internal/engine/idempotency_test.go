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
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func dueClock(now time.Time) string {
	candidate := now.Add(-time.Minute)
	if candidate.Day() != now.Day() {
		return now.Format("15:04")
	}
	return candidate.Format("15:04")
}

func TestScheduledStartIsIdempotentAcrossCycles(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().In(loc)
	start := dueClock(now)
	stop := now.Add(6 * time.Hour).Format("15:04")
	st, account := setupAccount(t, func(config *domain.Config) {
		config.Accounts[0].ScheduleEnabled = true
		config.Accounts[0].StartTime = start
		config.Accounts[0].StopTime = stop
	})
	defer st.Close()
	provider := newFakeProvider()
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	if _, err = eng.processAccount(ctx, account.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err = eng.processAccount(ctx, account.ID, false); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 1 || got[0] != "start" {
		t.Fatalf("controls = %#v", got)
	}
}

func TestThresholdStopIsIdempotentUntilCleared(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	provider := newFakeProvider()
	provider.traffic = 200
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	if _, err := eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 1 || got[0] != "stop" {
		t.Fatalf("controls = %#v", got)
	}
	provider.traffic = 1
	if _, err := eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	provider.traffic = 200
	if _, err := eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 2 || got[1] != "stop" {
		t.Fatalf("cleared threshold should be allowed to fire again, controls = %#v", got)
	}
}

func TestFailedScheduledActionCanRetry(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().In(loc)
	start := dueClock(now)
	stop := now.Add(6 * time.Hour).Format("15:04")
	st, account := setupAccount(t, func(config *domain.Config) {
		config.Accounts[0].ScheduleEnabled = true
		config.Accounts[0].StartTime = start
		config.Accounts[0].StopTime = stop
	})
	defer st.Close()
	provider := newFakeProvider()
	provider.controlErr = errors.New("aliyun unavailable")
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	if _, err = eng.processAccount(ctx, account.ID, false); err == nil {
		t.Fatal("expected scheduled start to fail")
	}
	if got := provider.controlActions(); len(got) != 1 {
		t.Fatalf("controls after failure = %#v", got)
	}
	provider.controlErr = nil
	if _, err = eng.processAccount(ctx, account.ID, false); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 2 || got[1] != "start" {
		t.Fatalf("failed schedule should retry, controls = %#v", got)
	}
}
