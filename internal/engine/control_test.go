package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/notify"
)

func TestManualStartAllowedWhenStatusUnknown(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	if account.InstanceStatus != domain.StatusUnknown {
		t.Fatalf("setup status = %q", account.InstanceStatus)
	}
	provider := newFakeProvider()
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	job := domain.Job{Type: JobControlInstance, AccountID: account.ID, Payload: ParseControlPayload("START", "手动")}
	if _, err := eng.runJob(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if got := provider.controlActions(); len(got) != 1 || got[0] != "start" {
		t.Fatalf("controls = %#v", got)
	}
}

func TestManualStopRejectedWhileStarting(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	ctx := context.Background()
	if err := st.UpdateRuntime(ctx, account.ID, 1.25, domain.StatusStarting, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	provider := newFakeProvider()
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	_, err := eng.runJob(ctx, domain.Job{Type: JobControlInstance, AccountID: account.ID, Payload: ParseControlPayload("stop", "手动")})
	if err == nil || !strings.Contains(err.Error(), domain.StatusStarting) {
		t.Fatalf("expected in-flight rejection, err=%v", err)
	}
	if got := provider.controlActions(); len(got) != 0 {
		t.Fatalf("in-flight stop must not call Aliyun, controls = %#v", got)
	}
}

func TestManualStartRejectedWhilePending(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	ctx := context.Background()
	if err := st.UpdateRuntime(ctx, account.ID, 1.25, "Pending", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	provider := newFakeProvider()
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	_, err := eng.runJob(ctx, domain.Job{Type: JobControlInstance, AccountID: account.ID, Payload: ParseControlPayload("start", "手动")})
	if err == nil || !strings.Contains(err.Error(), "Pending") {
		t.Fatalf("expected pending rejection, err=%v", err)
	}
	if got := provider.controlActions(); len(got) != 0 {
		t.Fatalf("pending start must not call Aliyun, controls = %#v", got)
	}
}

func TestControlJobsShareUniqueKeyUntilComplete(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	eng := New(st, newFakeProvider(), notify.New(), quietLogger(), 1)
	ctx := context.Background()
	key := JobUniqueKey(JobControlInstance, account.ID, "start")
	first, err := eng.Enqueue(ctx, JobControlInstance, account.ID, ParseControlPayload("start", "手动"), key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := eng.Enqueue(ctx, JobControlInstance, account.ID, ParseControlPayload("start", "手动"), key)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("duplicate control job %s vs %s", first.ID, second.ID)
	}
	if _, err = eng.runJob(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err = st.CompleteJob(ctx, first.ID, "ok"); err != nil {
		t.Fatal(err)
	}
	third, err := eng.Enqueue(ctx, JobControlInstance, account.ID, ParseControlPayload("start", "手动"), key)
	if err != nil {
		t.Fatal(err)
	}
	if third.ID == first.ID {
		t.Fatal("completed control job should release unique_key")
	}
}

func TestScheduledStopIsIdempotentAcrossCycles(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().In(loc)
	stop := dueClock(now)
	start := now.Add(6 * time.Hour).Format("15:04")
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
	if got := provider.controlActions(); len(got) != 1 || got[0] != "stop" {
		t.Fatalf("controls = %#v", got)
	}
}
