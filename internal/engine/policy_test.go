package engine

import (
	"testing"
	"time"
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

func TestRegionNameIncludesTokyoAndShanghai(t *testing.T) {
	if name := RegionName("ap-northeast-1"); name != "日本（东京）" {
		t.Fatalf("tokyo got %q", name)
	}
	if name := RegionName("cn-shanghai"); name != "华东 2（上海）" {
		t.Fatalf("shanghai got %q", name)
	}
}
