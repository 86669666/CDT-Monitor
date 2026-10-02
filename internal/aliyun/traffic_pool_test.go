package aliyun

import (
	"github.com/wang4386/CDT-Monitor/internal/domain"
	"testing"
	"time"
)

func TestTrafficCacheBillingMonthBoundary(t *testing.T) {
	a := domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-beijing"}
	before := time.Date(2026, 10, 31, 15, 59, 59, 0, time.UTC)
	after := before.Add(time.Second)
	if trafficCacheKey(a, before) == trafficCacheKey(a, after) {
		t.Fatal("CDT month boundary reused old usage")
	}
	b := a
	b.RegionID = "cn-shanghai"
	if trafficCacheKey(a, after) != trafficCacheKey(b, after) {
		t.Fatal("mainland instances should share cache")
	}
	b.RegionID = "cn-hongkong"
	if trafficCacheKey(a, after) == trafficCacheKey(b, after) {
		t.Fatal("Hong Kong must use international pool")
	}
}
