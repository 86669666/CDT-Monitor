package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/notify"
)

func TestFailedTrafficFetchDoesNotStopOnStaleUsage(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	ctx := context.Background()
	if err := st.UpdateRuntime(ctx, account.ID, 200, domain.StatusRunning, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	provider := newFakeProvider()
	provider.traffic = 200
	provider.trafficErr = errors.New("cdt unavailable")
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	if _, err := eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 0 {
		t.Fatalf("stale traffic after a failed poll must not stop, controls = %#v", got)
	}
	provider.trafficErr = nil
	if _, err := eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 1 || got[0] != "stop" {
		t.Fatalf("fresh over-threshold poll should stop once, controls = %#v", got)
	}
}

func TestFailedStatusFetchDoesNotKeepAlive(t *testing.T) {
	st, account := setupAccount(t, func(config *domain.Config) {
		config.KeepAlive = true
	})
	defer st.Close()
	ctx := context.Background()
	if err := st.UpdateRuntime(ctx, account.ID, 1.25, domain.StatusStopped, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	provider := newFakeProvider()
	provider.status = domain.StatusStopped
	provider.statusErr = errors.New("ecs unavailable")
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	if _, err := eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 0 {
		t.Fatalf("failed status poll must not keep-alive, controls = %#v", got)
	}
	provider.statusErr = nil
	if _, err := eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 1 || got[0] != "start" {
		t.Fatalf("fresh stopped poll should keep-alive once, controls = %#v", got)
	}
}
