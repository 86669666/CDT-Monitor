package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// TrafficClass describes the CDT billing area, independently of the BSS site.
func TrafficClass(region string) string {
	if strings.HasPrefix(region, "cn-") && region != "cn-hongkong" {
		return "china"
	}
	return "international"
}

func DefaultTrafficQuota(region string) float64 {
	if TrafficClass(region) == "china" {
		return 20
	}
	return 200
}

// TrafficPoolID groups a single credential's observations. Different credentials
// may belong to the same cloud account; we cannot infer that from masked IDs.
func TrafficPoolID(account Account) string {
	sum := sha256.Sum256([]byte(account.AccessKeyID + "\x00" + TrafficClass(account.RegionID)))
	return hex.EncodeToString(sum[:])
}

func TrafficMonth(at time.Time) string {
	return at.In(time.FixedZone("CDT", 8*60*60)).Format("2006-01")
}

// LatestTrafficSamples selects observations, never sums copies of pool usage.
// The latest successful sample wins even when a monthly reset lowers usage.
func LatestTrafficSamples(accounts []Account) map[string]Account {
	result := make(map[string]Account)
	for _, account := range accounts {
		key := TrafficPoolID(account)
		previous, exists := result[key]
		if !exists || account.UpdatedAt.After(previous.UpdatedAt) || (account.UpdatedAt.Equal(previous.UpdatedAt) && account.ID < previous.ID) {
			result[key] = account
		}
	}
	return result
}

// ConflictingTrafficPools keeps legacy configuration readable but prevents
// ambiguous pool thresholds from silently controlling instances.
func ConflictingTrafficPools(accounts []Account) map[string]bool {
	quotas := make(map[string]float64)
	conflicts := make(map[string]bool)
	for _, account := range accounts {
		key := TrafficPoolID(account)
		if quota, ok := quotas[key]; ok && quota != account.MaxTraffic {
			conflicts[key] = true
		}
		quotas[key] = account.MaxTraffic
	}
	return conflicts
}
