package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/notify"
	"github.com/wang4386/CDT-Monitor/internal/store"
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

func TestKeepAliveDoesNotStartWhenStatusUnknown(t *testing.T) {
	st, account := setupAccount(t, func(config *domain.Config) {
		config.KeepAlive = true
	})
	defer st.Close()
	ctx := context.Background()
	if err := st.UpdateRuntime(ctx, account.ID, 1.25, domain.StatusStopped, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	provider := newFakeProvider()
	provider.status = domain.StatusUnknown
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	if _, err := eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 0 {
		t.Fatalf("unknown status must not keep-alive, controls = %#v", got)
	}
}

func TestKeepAliveDoesNotStartWhenStarting(t *testing.T) {
	st, account := setupAccount(t, func(config *domain.Config) {
		config.KeepAlive = true
	})
	defer st.Close()
	ctx := context.Background()
	if err := st.UpdateRuntime(ctx, account.ID, 1.25, domain.StatusStopped, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	provider := newFakeProvider()
	provider.status = domain.StatusStarting
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	if _, err := eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 0 {
		t.Fatalf("starting instance must not keep-alive, controls = %#v", got)
	}
}

func TestKeepAliveStartIsIndependentPerAccount(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	config := domain.Config{
		AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging",
		ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai",
		KeepAlive: true,
		Accounts: []domain.Account{
			{AccessKeyID: "LTAIone", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-one", MaxTraffic: 200, SiteType: "china"},
			{AccessKeyID: "LTAItwo", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-two", MaxTraffic: 200, SiteType: "china"},
		},
	}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	accounts, err := st.ListAccounts(ctx)
	if err != nil || len(accounts) != 2 {
		t.Fatalf("accounts=%v err=%v", accounts, err)
	}
	provider := newFakeProvider()
	provider.status = domain.StatusStopped
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	if _, err = eng.processAccount(ctx, accounts[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err = eng.processAccount(ctx, accounts[1].ID, true); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 2 || got[0] != "start" || got[1] != "start" {
		t.Fatalf("both stopped accounts should keep-alive once, controls = %#v", got)
	}
	if err = st.UpdateRuntime(ctx, accounts[0].ID, 1.25, domain.StatusStopped, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err = st.UpdateRuntime(ctx, accounts[1].ID, 1.25, domain.StatusStopped, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err = eng.processAccount(ctx, accounts[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err = eng.processAccount(ctx, accounts[1].ID, true); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 2 {
		t.Fatalf("keepalive events must stay per-account, controls = %#v", got)
	}
}
