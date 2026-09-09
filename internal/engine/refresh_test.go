package engine

import (
	"context"
	"testing"

	"github.com/wang4386/CDT-Monitor/internal/notify"
)

func TestEnqueueRefreshAllDeduplicatesWithinTheMinute(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	provider := newFakeProvider()
	provider.traffic = 4.5
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	first, err := eng.EnqueueRefreshAll(ctx)
	if err != nil || len(first) != 1 || first[0].AccountID != account.ID || first[0].Type != JobRefreshAccount {
		t.Fatalf("first refresh jobs = %#v err=%v", first, err)
	}
	second, err := eng.EnqueueRefreshAll(ctx)
	if err != nil || len(second) != 1 || second[0].ID != first[0].ID {
		t.Fatalf("duplicate refresh jobs = %#v err=%v", second, err)
	}
	claimed, err := st.ClaimJob(ctx)
	if err != nil || claimed.ID != first[0].ID {
		t.Fatalf("claimed = %#v err=%v", claimed, err)
	}
	if _, err = eng.runJob(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	if err = st.CompleteJob(ctx, claimed.ID, "ok"); err != nil {
		t.Fatal(err)
	}
	updated, err := st.GetAccount(ctx, account.ID)
	if err != nil || updated.TrafficUsed != 4.5 {
		t.Fatalf("account after refresh = %#v err=%v", updated, err)
	}
	third, err := eng.EnqueueRefreshAll(ctx)
	if err != nil || len(third) != 1 {
		t.Fatalf("post-complete refresh jobs = %#v err=%v", third, err)
	}
	if third[0].ID == first[0].ID {
		t.Fatal("completed refresh job should release unique_key")
	}
}
