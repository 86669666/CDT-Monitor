package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/wang4386/CDT-Monitor/internal/aliyun"
	"github.com/wang4386/CDT-Monitor/internal/domain"
	"time"
)

type instanceMetadata struct {
	Identity   string    `json:"identity"`
	Kind       string    `json:"kind"`
	ObservedAt time.Time `json:"observed_at"`
	Failed     bool      `json:"failed"`
}

func instanceMetadataIdentity(a domain.Account) string {
	sum := sha256.Sum256([]byte(a.AccessKeyID + "\x00" + a.RegionID + "\x00" + a.InstanceID))
	return hex.EncodeToString(sum[:])
}

func (e *Engine) refreshInstanceMetadata(ctx context.Context, a domain.Account, secret string) {
	p, ok := e.provider.(aliyun.InstanceMetadataProvider)
	if !ok {
		return
	}
	cached := instanceMetadata{Identity: instanceMetadataIdentity(a), Kind: "unknown"}
	var previous instanceMetadata
	if ok, err := e.store.BillingCache(ctx, a.ID, "instance_metadata", "", 7*24*time.Hour, &previous); err == nil && ok && previous.Identity == cached.Identity {
		cached = previous
	}
	// A metadata error must never prevent traffic/status collection or cloud controls.
	cached.Failed = true
	defer func() {
		if recover() != nil {
			cached.Failed = true
		}
		_ = e.store.SetBillingCache(ctx, a.ID, "instance_metadata", "", cached)
	}()
	kind, err := p.GetInstanceChargeType(ctx, a, secret)
	if err != nil {
		return
	}
	switch kind {
	case "subscription", "spot", "pay_as_you_go", "unknown":
	default:
		kind = "unknown"
	}
	cached.Kind, cached.ObservedAt, cached.Failed = kind, time.Now().UTC(), false
}

func (e *Engine) applyInstanceMetadata(ctx context.Context, a domain.Account, interval int, item *domain.AccountSummary) {
	item.InstanceChargeType, item.InstanceTypeStale = "unknown", true
	var cached instanceMetadata
	if ok, err := e.store.BillingCache(ctx, a.ID, "instance_metadata", "", 7*24*time.Hour, &cached); err != nil || !ok || cached.Identity != instanceMetadataIdentity(a) {
		return
	}
	switch cached.Kind {
	case "subscription", "spot", "pay_as_you_go", "unknown":
	default:
		return
	}
	item.InstanceChargeType, item.InstanceTypeUpdatedAt = cached.Kind, cached.ObservedAt
	item.InstanceTypeStale = cached.Failed || cached.ObservedAt.IsZero() || time.Since(cached.ObservedAt) > time.Duration(max(interval*2, 180))*time.Second
}
