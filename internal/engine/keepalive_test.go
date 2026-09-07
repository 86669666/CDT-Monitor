package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/notify"
)

func TestKeepAliveStartIsIdempotentWithinTheMinute(t *testing.T) {
	st, account := setupAccount(t, func(config *domain.Config) {
		config.KeepAlive = true
	})
	defer st.Close()
	provider := newFakeProvider()
	provider.status = domain.StatusStopped
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	if _, err := eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateRuntime(ctx, account.ID, 1.25, domain.StatusStopped, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 1 || got[0] != "start" {
		t.Fatalf("keepalive should start once per minute, controls = %#v", got)
	}
}

func TestKeepAliveDoesNotStartWhenOverThreshold(t *testing.T) {
	st, account := setupAccount(t, func(config *domain.Config) {
		config.KeepAlive = true
	})
	defer st.Close()
	provider := newFakeProvider()
	provider.status = domain.StatusStopped
	provider.traffic = 200
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	if _, err := eng.processAccount(context.Background(), account.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 0 {
		t.Fatalf("over-threshold keepalive must not start instance, controls = %#v", got)
	}
}

func TestKeepAliveRespectsScheduleWindow(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().In(loc).Format("15:04")
	start, end := "02:00", "03:00"
	if inTimeRange(now, start, end) {
		start, end = "14:00", "15:00"
	}
	if inTimeRange(now, start, end) {
		t.Skip("current clock sits in both candidate off-windows")
	}
	st, account := setupAccount(t, func(config *domain.Config) {
		config.KeepAlive = true
		config.Accounts[0].ScheduleEnabled = true
		config.Accounts[0].StartTime = start
		config.Accounts[0].StopTime = end
	})
	defer st.Close()
	provider := newFakeProvider()
	provider.status = domain.StatusStopped
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	if _, err = eng.processAccount(context.Background(), account.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 0 {
		t.Fatalf("keepalive outside schedule window must not start, controls = %#v", got)
	}
}

func TestManualStopRejectedWhileKeepAliveEnabled(t *testing.T) {
	st, account := setupAccount(t, func(config *domain.Config) {
		config.KeepAlive = true
	})
	defer st.Close()
	if err := st.UpdateRuntime(context.Background(), account.ID, 1.25, domain.StatusRunning, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	provider := newFakeProvider()
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	_, err := eng.control(context.Background(), account.ID, "stop", "manual")
	if err == nil || !strings.Contains(err.Error(), "keep-alive") {
		t.Fatalf("expected keep-alive stop rejection, err=%v", err)
	}
	if got := provider.controlActions(); len(got) != 0 {
		t.Fatalf("rejected stop must not call Aliyun, controls = %#v", got)
	}
}
