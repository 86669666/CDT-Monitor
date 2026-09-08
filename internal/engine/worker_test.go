package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/wang4386/CDT-Monitor/internal/notify"
)

func TestProcessJobsCompletesRefreshFromFakeAliyun(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	provider := newFakeProvider()
	provider.traffic = 9.25
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	if _, err := eng.Enqueue(ctx, JobRefreshAccount, account.ID, `{}`, JobUniqueKey(JobRefreshAccount, account.ID, "test")); err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	updated, err := st.GetAccount(ctx, account.ID)
	if err != nil || updated.TrafficUsed != 9.25 {
		t.Fatalf("account = %#v err=%v", updated, err)
	}
	var status string
	if err = st.DB().QueryRowContext(ctx, `SELECT status FROM jobs WHERE account_id=?`, account.ID).Scan(&status); err != nil || status != "completed" {
		t.Fatalf("job status = %q err=%v", status, err)
	}
}

func TestProcessJobsRequeuesFailedControl(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	provider := newFakeProvider()
	provider.controlErr = errors.New("ecs unavailable")
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	job, err := eng.Enqueue(ctx, JobControlInstance, account.ID, ParseControlPayload("start", "手动"), JobUniqueKey(JobControlInstance, account.ID, "start"))
	if err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	var status, jobErr string
	if err = st.DB().QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id=?`, job.ID).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || jobErr == "" {
		t.Fatalf("failed control status=%q error=%q", status, jobErr)
	}
	if got := provider.controlActions(); len(got) != 1 || got[0] != "start" {
		t.Fatalf("controls = %#v", got)
	}
}
