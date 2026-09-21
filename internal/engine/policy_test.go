package engine

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/notify"
	"github.com/wang4386/CDT-Monitor/internal/store"
)

func TestDueWithinSupportsLateScheduler(t *testing.T) {
	location := time.FixedZone("CST", 8*3600)
	now := time.Date(2026, 7, 19, 8, 7, 0, 0, location)
	if !dueWithin(now, "08:00", 10*time.Minute) {
		t.Fatal("expected delayed scheduler to compensate")
	}
	if dueWithin(now, "07:50", 10*time.Minute) {
		t.Fatal("must not compensate outside the window")
	}
}

func TestInTimeRangeAcrossMidnight(t *testing.T) {
	if !inTimeRange("23:30", "22:00", "06:00") || !inTimeRange("05:59", "22:00", "06:00") {
		t.Fatal("cross-midnight window should include night times")
	}
	if inTimeRange("12:00", "22:00", "06:00") {
		t.Fatal("cross-midnight window must exclude midday")
	}
}

func TestUsagePercent(t *testing.T) {
	if value := usagePercent(95, 200); value != 47.5 {
		t.Fatalf("got %v", value)
	}
	if value := usagePercent(1, 0); value != 0 {
		t.Fatalf("zero quota got %v", value)
	}
}

func TestRegionNameIncludesSeoul(t *testing.T) {
	if name := RegionName("ap-northeast-2"); name != "韩国（首尔）" {
		t.Fatalf("got %q", name)
	}
}


func TestResolveKeepAliveAndShutdownMode(t *testing.T) {
	trueVal := true
	falseVal := false

	cfg := domain.Config{KeepAlive: true, ShutdownMode: "KeepCharging"}

	// Inherit
	accDefault := domain.Account{}
	if !resolveKeepAlive(accDefault, cfg) {
		t.Fatal("expected default account to inherit keep_alive=true")
	}
	if resolveShutdownMode(accDefault, cfg) != "KeepCharging" {
		t.Fatal("expected default account to inherit shutdown_mode=KeepCharging")
	}

	// Override keep alive
	accOverrideKA := domain.Account{KeepAlive: &falseVal}
	if resolveKeepAlive(accOverrideKA, cfg) {
		t.Fatal("expected account to override keep_alive=false")
	}

	// Override shutdown mode
	accOverrideSM := domain.Account{ShutdownMode: "StopCharging"}
	if resolveShutdownMode(accOverrideSM, cfg) != "StopCharging" {
		t.Fatal("expected account to override shutdown_mode=StopCharging")
	}

	// Global false, instance true
	cfgFalse := domain.Config{KeepAlive: false, ShutdownMode: "StopCharging"}
	accEnableKA := domain.Account{KeepAlive: &trueVal}
	if !resolveKeepAlive(accEnableKA, cfgFalse) {
		t.Fatal("expected account to override keep_alive=true")
	}
}

func TestDailyReportGenerationAndExclusion(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := t.Context()

	trueVal := true
	falseVal := false

	cfg := domain.Config{
		AdminPassword:     "Strong-Password-42!",
		TrafficThreshold:  95,
		ShutdownMode:      "KeepCharging",
		ThresholdAction:   "stop_and_notify",
		APIInterval:       600,
		Timezone:          "Asia/Shanghai",
		EnableDailyReport: true,
		DailyReportTime:   "22:00",
		Notifications: domain.NotificationConfig{
			Webhook: domain.WebhookConfig{
				Enabled: true,
				URL:     "https://webhook.example.com/test",
			},
		},
		Accounts: []domain.Account{
			{
				AccessKeyID:      "LTAI1",
				AccessKeySecret:  "sec1",
				RegionID:         "cn-hongkong",
				InstanceID:       "i-hk",
				MaxTraffic:       200,
				Remark:           "香港节点",
				ScheduleEnabled:  true,
				StartTime:        "08:00",
				StopTime:         "22:00",
				DailyReport:      &trueVal, // Included
			},
			{
				AccessKeyID:      "LTAI2",
				AccessKeySecret:  "sec2",
				RegionID:         "ap-northeast-1",
				InstanceID:       "i-jp",
				MaxTraffic:       100,
				Remark:           "东京节点",
				DailyReport:      nil, // Default -> Included
			},
			{
				AccessKeyID:      "LTAI3",
				AccessKeySecret:  "sec3",
				RegionID:         "us-west-1",
				InstanceID:       "i-us",
				MaxTraffic:       300,
				Remark:           "硅谷节点",
				DailyReport:      &falseVal, // Excluded!
			},
		},
	}
	if err = st.Setup(ctx, cfg); err != nil {
		t.Fatal(err)
	}

	eng := New(st, nil, notify.New(), nil, 1)

	// Set traffic for accounts
	accs, _ := st.ListAccounts(ctx)
	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Now().In(loc)
	// Record snapshots
	_ = st.UpdateRuntime(ctx, accs[0].ID, 15.0, domain.StatusStopped, now)
	_ = st.RecordTrafficSnapshot(ctx, accs[0].ID, now.Format("2006-01-02"), "start", 10.0, "08:00")
	_ = st.RecordTrafficSnapshot(ctx, accs[0].ID, now.Format("2006-01-02"), "stop", 14.5, "22:00")

	_ = st.UpdateRuntime(ctx, accs[1].ID, 8.0, domain.StatusRunning, now)
	// For accs[1] (non-scheduled), baseline traffic 24 hours ago = 5.0
	t24Ago := now.Add(-24 * time.Hour)
	_ = st.AddTrafficStats(ctx, accs[1].ID, 5.0, t24Ago)
	_ = st.AddTrafficStats(ctx, accs[1].ID, 8.0, now)

	_ = st.UpdateRuntime(ctx, accs[2].ID, 20.0, domain.StatusRunning, now)

	result, err := eng.generateAndSendDailyReport(ctx, true)
	if err != nil {
		t.Fatalf("generateAndSendDailyReport failed: %v", err)
	}
	if result == "" {
		t.Fatal("expected non-empty result message")
	}

	outboxItem, err := st.ClaimOutbox(ctx)
	if err != nil {
		t.Fatalf("expected daily report in outbox: %v", err)
	}
	var event domain.NotificationEvent
	if err = json.Unmarshal([]byte(outboxItem.Payload), &event); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	if event.Type != "daily_report" {
		t.Fatalf("event.Type = %s, want daily_report", event.Type)
	}
	if event.Fields["纳入实例"] != "2 台" {
		t.Fatalf("expected 2 included accounts, got %s", event.Fields["纳入实例"])
	}
	if event.Fields["排除实例"] != "1 台" {
		t.Fatalf("expected 1 excluded account, got %s", event.Fields["排除实例"])
	}

	// accs[0] consumed = 14.5 - 10.0 = 4.5 GB
	// accs[1] consumed = 8.0 - 5.0 = 3.0 GB
	// total consumed = 7.50 GB
	if event.Fields["流量消耗总和"] != "7.50 GB" {
		t.Fatalf("expected 7.50 GB total consumed, got %s", event.Fields["流量消耗总和"])
	}
}

func TestDailyReportSmallAmountPrecisionAndSingleInstance(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := t.Context()

	cfg := domain.Config{
		AdminPassword:     "Strong-Password-42!",
		TrafficThreshold:  95,
		ShutdownMode:      "KeepCharging",
		ThresholdAction:   "stop_and_notify",
		APIInterval:       600,
		Timezone:          "Asia/Shanghai",
		EnableDailyReport: true,
		Notifications: domain.NotificationConfig{
			Webhook: domain.WebhookConfig{
				Enabled: true,
				URL:     "https://webhook.example.com/test",
			},
		},
		Accounts: []domain.Account{
			{
				AccessKeyID:      "LTAI_PRECISION",
				AccessKeySecret:  "sec",
				RegionID:         "cn-hongkong",
				InstanceID:       "i-precision",
				MaxTraffic:       200,
				Remark:           "高精度测试节点",
				ScheduleEnabled:  false,
				DailyReportTime:  "00:00",
			},
		},
	}
	if err = st.Setup(ctx, cfg); err != nil {
		t.Fatal(err)
	}

	eng := New(st, nil, notify.New(), nil, 1)
	accs, _ := st.ListAccounts(ctx)
	acc := accs[0]

	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Now().In(loc)
	t24Ago := now.Add(-24 * time.Hour)

	// Baseline 24 hours ago was 1.000 GB, current is 1.292 GB -> consumed = 0.292 GB
	_ = st.AddTrafficStats(ctx, acc.ID, 1.000, t24Ago)
	_ = st.UpdateRuntime(ctx, acc.ID, 1.292, domain.StatusRunning, now)

	result, err := eng.generateAndSendDailyReport(ctx, true, acc.ID)
	if err != nil {
		t.Fatalf("generateAndSendDailyReport failed: %v", err)
	}
	if !strings.Contains(result, "0.292 GB") {
		t.Fatalf("expected result message to contain 0.292 GB, got: %s", result)
	}

	outboxItem, err := st.ClaimOutbox(ctx)
	if err != nil {
		t.Fatalf("expected outbox item: %v", err)
	}
	var event domain.NotificationEvent
	if err = json.Unmarshal([]byte(outboxItem.Payload), &event); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if event.Fields["消耗流量"] != "0.292 GB" {
		t.Fatalf("expected 0.292 GB in event fields, got: %s", event.Fields["消耗流量"])
	}
	if !strings.Contains(event.Title, "高精度测试节点") {
		t.Fatalf("expected title to contain remark, got: %s", event.Title)
	}
}

func TestDailyReportFallbackWhenNo24HourData(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := t.Context()

	cfg := domain.Config{
		AdminPassword:     "Strong-Password-42!",
		TrafficThreshold:  95,
		ShutdownMode:      "KeepCharging",
		ThresholdAction:   "stop_and_notify",
		APIInterval:       600,
		Timezone:          "Asia/Shanghai",
		EnableDailyReport: true,
		Notifications: domain.NotificationConfig{
			Webhook: domain.WebhookConfig{
				Enabled: true,
				URL:     "https://webhook.example.com/test",
			},
		},
		Accounts: []domain.Account{
			{
				AccessKeyID:     "LTAI_FALLBACK",
				AccessKeySecret: "sec",
				RegionID:        "cn-hongkong",
				InstanceID:      "i-fallback",
				MaxTraffic:      200,
				Remark:          "回退测试节点",
				ScheduleEnabled: false,
				DailyReportTime: "00:00",
			},
		},
	}
	if err = st.Setup(ctx, cfg); err != nil {
		t.Fatal(err)
	}

	eng := New(st, nil, notify.New(), nil, 1)
	accs, _ := st.ListAccounts(ctx)
	acc := accs[0]

	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Now().In(loc)

	_ = st.AddTrafficStats(ctx, acc.ID, 2.0, now.Add(-2*time.Hour))
	_ = st.AddTrafficStats(ctx, acc.ID, 2.5, now)
	_ = st.UpdateRuntime(ctx, acc.ID, 2.5, domain.StatusRunning, now)

	result, err := eng.generateAndSendDailyReport(ctx, true, acc.ID)
	if err != nil {
		t.Fatalf("generateAndSendDailyReport failed: %v", err)
	}
	if strings.Contains(result, "0.00 GB") {
		t.Fatalf("consumed should not be 0 when fallback data is available, got: %s", result)
	}
	if !strings.Contains(result, "0.50 GB") && !strings.Contains(result, "0.500 GB") {
		t.Fatalf("expected consumed ~0.5 GB from fallback, got: %s", result)
	}
}
