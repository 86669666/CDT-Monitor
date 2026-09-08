package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/wang4386/CDT-Monitor/internal/notify"
)

func TestProcessAccountWritesTrafficHistory(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	provider := newFakeProvider()
	provider.traffic = 7.5
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	if _, err := eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	history, err := st.History(ctx, account.ID)
	if err != nil || len(history.Hourly) != 1 || history.Hourly[0].Traffic != 7.5 || len(history.Daily) != 1 {
		t.Fatalf("history = %#v err=%v", history, err)
	}
	provider.trafficErr = errors.New("cdt unavailable")
	provider.traffic = 99
	if _, err = eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	history, err = st.History(ctx, account.ID)
	if err != nil || len(history.Hourly) != 1 || history.Hourly[0].Traffic != 7.5 {
		t.Fatalf("failed poll must not overwrite history, got %#v err=%v", history, err)
	}
}
