package engine

import (
	"context"
	"testing"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/notify"
)

func TestSummaryMarksStaleAccounts(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	eng := New(st, newFakeProvider(), notify.New(), quietLogger(), 1)
	ctx := context.Background()
	summaries, _, err := eng.Summary(ctx)
	if err != nil || len(summaries) != 1 || !summaries[0].Stale {
		t.Fatalf("zero UpdatedAt should be stale, summaries=%#v err=%v", summaries, err)
	}
	if summaries[0].Account != "LTAItes***" {
		t.Fatalf("summary must mask access key, got %q", summaries[0].Account)
	}
	if err = st.UpdateRuntime(ctx, account.ID, 1.5, domain.StatusRunning, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	summaries, _, err = eng.Summary(ctx)
	if err != nil || len(summaries) != 1 || summaries[0].Stale || summaries[0].FlowUsed != 1.5 {
		t.Fatalf("fresh update should not be stale, summaries=%#v err=%v", summaries, err)
	}
	if err = st.UpdateRuntime(ctx, account.ID, 1.5, domain.StatusRunning, time.Now().UTC().Add(-30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	summaries, _, err = eng.Summary(ctx)
	if err != nil || len(summaries) != 1 || !summaries[0].Stale {
		t.Fatalf("30m-old update should be stale at 600s interval, summaries=%#v err=%v", summaries, err)
	}
}

func TestSummaryMarksOverThreshold(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	eng := New(st, newFakeProvider(), notify.New(), quietLogger(), 1)
	ctx := context.Background()
	if err := st.UpdateRuntime(ctx, account.ID, 189, domain.StatusRunning, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	summaries, _, err := eng.Summary(ctx)
	if err != nil || len(summaries) != 1 || summaries[0].OverThreshold || summaries[0].Percentage != 94.5 {
		t.Fatalf("under threshold summaries=%#v err=%v", summaries, err)
	}
	if err = st.UpdateRuntime(ctx, account.ID, 190, domain.StatusRunning, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	summaries, _, err = eng.Summary(ctx)
	if err != nil || len(summaries) != 1 || !summaries[0].OverThreshold || summaries[0].Percentage != 95 {
		t.Fatalf("at threshold summaries=%#v err=%v", summaries, err)
	}
}
