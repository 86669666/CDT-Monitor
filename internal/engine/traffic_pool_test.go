package engine

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/notify"
)

func TestSharedTrafficSummaryAndThresholds(t *testing.T) {
	st, first := setupAccount(t, func(c *domain.Config) {
		c.Accounts[0].RegionID = "cn-beijing"
		c.Accounts[0].MaxTraffic = 20
	})
	defer st.Close()
	ctx := context.Background()
	c, _ := st.GetConfig(ctx)
	second := c.Accounts[0]
	second.ID, second.RegionID, second.InstanceID = 0, "cn-shanghai", "i-second"
	hk := second
	hk.RegionID, hk.MaxTraffic, hk.InstanceID = "cn-hongkong", 200, "i-hk"
	other := second
	other.AccessKeyID, other.AccessKeySecret, other.InstanceID = "LTAItest-other", "other-secret", "i-other"
	c.Accounts = append(c.Accounts, second, hk, other)
	if err := st.SaveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	c, _ = st.GetConfig(ctx)
	now := time.Now().UTC().Truncate(time.Second)
	for i, a := range c.Accounts {
		value, at := float64(90), now.Add(-time.Minute)
		if i == 1 {
			value, at = 0, now
		} // A zero after reset is newer, not smaller evidence.
		if err := st.UpdateRuntime(ctx, a.ID, value, domain.StatusRunning, at); err != nil {
			t.Fatal(err)
		}
	}
	provider := newFakeProvider()
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	summary, _, err := eng.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary[0].TrafficPoolID != summary[1].TrafficPoolID || summary[0].TrafficPoolInstanceCount != 2 || summary[0].FlowUsed != 0 || summary[1].FlowUsed != 0 || summary[0].FlowTotal != 20 {
		t.Fatalf("pool mismatch: %+v", summary)
	}
	if summary[0].TrafficPoolID == summary[2].TrafficPoolID || summary[0].TrafficPoolID == summary[3].TrafficPoolID || summary[2].FlowTotal != 200 {
		t.Fatal("independent pools merged")
	}
	if strings.Contains(summary[0].TrafficPoolID, first.AccessKeyID) {
		t.Fatal("pool ID exposes key")
	}
	provider.traffic = 19
	for _, a := range c.Accounts[:2] {
		if _, err := eng.processAccount(ctx, a.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	if got := provider.controlActions(); len(got) != 2 || got[0] != "stop" || got[1] != "stop" {
		t.Fatalf("shared 95%% threshold not applied: %v", got)
	}
	summary, _, _ = eng.Summary(ctx)
	if summary[0].Percentage != 95 || summary[1].Percentage != 95 {
		t.Fatal("threshold percentages differ")
	}
}

func TestFailedTrafficDoesNotStartAndControlPreservesSampleTime(t *testing.T) {
	st, a := setupAccount(t, func(c *domain.Config) { c.KeepAlive = true })
	defer st.Close()
	ctx := context.Background()
	at := time.Now().UTC().AddDate(0, -1, 0).Truncate(time.Second)
	if err := st.UpdateRuntime(ctx, a.ID, 0, domain.StatusStopped, at); err != nil {
		t.Fatal(err)
	}
	p := newFakeProvider()
	p.status, p.trafficErr = domain.StatusStopped, errors.New("offline")
	e := New(st, p, notify.New(), quietLogger(), 1)
	if _, err := e.processAccount(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	if len(p.controlActions()) != 0 {
		t.Fatal("failed old-month traffic must not start instance")
	}
	if err := st.UpdateInstanceStatus(ctx, a.ID, domain.StatusStarting); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetAccount(ctx, a.ID)
	if !got.UpdatedAt.Equal(at) || got.TrafficUsed != 0 {
		t.Fatal("status overwrote traffic observation")
	}
	summary, _, _ := e.Summary(ctx)
	if !summary[0].TrafficStale {
		t.Fatal("old-month sample marked fresh")
	}
}

func TestDailyReportDeduplicatesSharedPools(t *testing.T) {
	st, _ := setupAccount(t, func(c *domain.Config) {
		c.EnableDailyReport = true
		c.Notifications.Webhook = domain.WebhookConfig{Enabled: true, URL: "https://example.test/hook"}
		c.Accounts[0].RegionID, c.Accounts[0].MaxTraffic = "cn-beijing", 20
	})
	defer st.Close()
	ctx := context.Background()
	c, _ := st.GetConfig(ctx)
	second := c.Accounts[0]
	second.ID, second.RegionID, second.InstanceID = 0, "cn-shanghai", "i-two"
	c.Accounts = append(c.Accounts, second)
	if err := st.SaveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	c, _ = st.GetConfig(ctx)
	for _, a := range c.Accounts {
		if err := st.UpdateRuntime(ctx, a.ID, 5, domain.StatusRunning, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	e := New(st, nil, notify.New(), quietLogger(), 1)
	if _, err := e.generateAndSendDailyReport(ctx, false); err != nil {
		t.Fatal(err)
	}
	out, err := st.ClaimOutbox(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var event domain.NotificationEvent
	if err := json.Unmarshal([]byte(out.Payload), &event); err != nil {
		t.Fatal(err)
	}
	if event.Fields["当月累计流量"] != "5.00 GB / 20 GB" {
		t.Fatalf("duplicate pool totals: %v", event.Fields)
	}
	if !strings.Contains(event.Fields["流量消耗总和"], "不相加") {
		t.Fatal("overlapping windows summed")
	}
}
