package engine

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/aliyun"
	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/notify"
	"github.com/wang4386/CDT-Monitor/internal/store"
)

func TestProcessAccountFetchesMissingBillingCache(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	config := domain.Config{
		AdminPassword:    "Strong-Password-42!",
		TrafficThreshold: 95,
		ShutdownMode:     "KeepCharging",
		ThresholdAction:  "stop_and_notify",
		APIInterval:      600,
		EnableBilling:    true,
		Timezone:         "Asia/Shanghai",
		Accounts: []domain.Account{{
			AccessKeyID: "LTAItest", AccessKeySecret: "secret", RegionID: "cn-hongkong", InstanceID: "i-test", MaxTraffic: 200, SiteType: "china",
		}},
	}
	if err = st.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}
	accounts, err := st.ListAccounts(ctx)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("accounts=%v err=%v", accounts, err)
	}

	engine := New(st, newFakeProvider(), notify.New(), slog.Default(), 1)
	if _, err = engine.processAccount(ctx, accounts[0].ID, false); err != nil {
		t.Fatal(err)
	}

	var balance aliyun.BillingBalance
	if ok, err := st.BillingCache(ctx, accounts[0].ID, "balance", "", time.Hour, &balance); err != nil || !ok || balance.Amount != 123.45 {
		t.Fatalf("balance cache ok=%v value=%#v err=%v", ok, balance, err)
	}
	var bill aliyun.BillingBill
	if ok, err := st.BillingCache(ctx, accounts[0].ID, "instance_bill", time.Now().Format("2006-01"), time.Hour, &bill); err != nil || !ok || bill.TotalCost != 23.456 {
		t.Fatalf("bill cache ok=%v value=%#v err=%v", ok, bill, err)
	}
	summaries, _, err := engine.Summary(ctx)
	if err != nil || len(summaries) != 1 || summaries[0].Balance == nil || *summaries[0].Balance != 123.45 || summaries[0].MonthlyCost == nil || *summaries[0].MonthlyCost != 23.456 {
		t.Fatalf("summary=%#v err=%v", summaries, err)
	}
}

func TestBillingErrorIsCachedThenCleared(t *testing.T) {
	st, account := setupAccount(t, func(config *domain.Config) {
		config.EnableBilling = true
	})
	defer st.Close()
	provider := newFakeProvider()
	provider.balanceErr = errors.New("bss unavailable")
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	if _, err := eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	summaries, _, err := eng.Summary(ctx)
	if err != nil || len(summaries) != 1 || summaries[0].BillingError != "bss unavailable" || summaries[0].Balance != nil {
		t.Fatalf("error summary=%#v err=%v", summaries, err)
	}
	logs, err := st.ListLogs(ctx, "action", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range logs {
		if strings.Contains(strings.ToLower(entry.Message), "secret") {
			t.Fatalf("billing error log leaked secret: %q", entry.Message)
		}
	}
	provider.balanceErr = nil
	if _, err = eng.processAccount(ctx, account.ID, true); err != nil {
		t.Fatal(err)
	}
	summaries, _, err = eng.Summary(ctx)
	if err != nil || len(summaries) != 1 || summaries[0].BillingError != "" || summaries[0].Balance == nil || *summaries[0].Balance != 123.45 {
		t.Fatalf("recovered summary=%#v err=%v", summaries, err)
	}
}
