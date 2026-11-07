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
	Identity            string    `json:"identity"`
	Kind                string    `json:"kind"`
	ObservedAt          time.Time `json:"observed_at"`
	Failed              bool      `json:"failed"`
	PublicIPv4          string    `json:"public_ipv4,omitempty"`
	IPv6                string    `json:"ipv6,omitempty"`
	AddressesObservedAt time.Time `json:"addresses_observed_at"`
	AddressesFailed     bool      `json:"addresses_failed"`
}

// InstanceAddresses is only returned by the administrator-only endpoint.
// The target fields let the dashboard reject stale responses after an edit.
type InstanceAddresses struct {
	AccountID   int64     `json:"account_id"`
	AccessKeyID string    `json:"access_key_id"`
	RegionID    string    `json:"region_id"`
	InstanceID  string    `json:"instance_id"`
	PublicIPv4  string    `json:"public_ipv4"`
	IPv6        string    `json:"ipv6"`
	ObservedAt  time.Time `json:"observed_at"`
	Observed    bool      `json:"observed"`
	Stale       bool      `json:"stale"`
}

func instanceMetadataIdentity(a domain.Account) string {
	sum := sha256.Sum256([]byte(a.AccessKeyID + "\x00" + a.RegionID + "\x00" + a.InstanceID))
	return hex.EncodeToString(sum[:])
}

func (e *Engine) refreshInstanceMetadata(ctx context.Context, a domain.Account, secret string) {
	provider, hasDetails := e.provider.(aliyun.InstanceDetailsProvider)
	legacy, hasLegacy := e.provider.(aliyun.InstanceMetadataProvider)
	if !hasDetails && !hasLegacy {
		return
	}
	cached := instanceMetadata{Identity: instanceMetadataIdentity(a), Kind: "unknown"}
	var previous instanceMetadata
	if ok, err := e.store.BillingCache(ctx, a.ID, "instance_metadata", "", 7*24*time.Hour, &previous); err == nil && ok && previous.Identity == cached.Identity {
		cached = previous
	}
	// A metadata error must never prevent traffic/status collection or cloud controls.
	cached.Failed, cached.AddressesFailed = true, true
	defer func() {
		if recover() != nil {
			cached.Failed = true
		}
		_ = e.store.SetBillingCache(ctx, a.ID, "instance_metadata", "", cached)
	}()
	var kind string
	if hasDetails {
		details, err := provider.GetInstanceMetadata(ctx, a, secret)
		if err != nil {
			return
		}
		kind = details.ChargeType
		cached.PublicIPv4, cached.IPv6 = details.PublicIPv4, details.IPv6
		cached.AddressesObservedAt, cached.AddressesFailed = time.Now().UTC(), false
	} else {
		var err error
		kind, err = legacy.GetInstanceChargeType(ctx, a, secret)
		if err != nil {
			return
		}
	}
	switch kind {
	case "subscription", "spot", "pay_as_you_go", "unknown":
	default:
		kind = "unknown"
	}
	cached.Kind, cached.ObservedAt, cached.Failed = kind, time.Now().UTC(), false
}

// InstanceAddresses reads existing cache only; it never calls the provider.
func (e *Engine) InstanceAddresses(ctx context.Context) ([]InstanceAddresses, error) {
	accounts, err := e.store.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	interval, err := e.store.MonitorInterval(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]InstanceAddresses, 0, len(accounts))
	for _, account := range accounts {
		if account.InstanceID == "" {
			continue
		}
		item := InstanceAddresses{AccountID: account.ID, AccessKeyID: account.AccessKeyID, RegionID: account.RegionID, InstanceID: account.InstanceID, Stale: true}
		var cached instanceMetadata
		if ok, cacheErr := e.store.BillingCache(ctx, account.ID, "instance_metadata", "", 7*24*time.Hour, &cached); cacheErr == nil && ok && cached.Identity == instanceMetadataIdentity(account) && !cached.AddressesObservedAt.IsZero() {
			item.PublicIPv4, item.IPv6 = cached.PublicIPv4, cached.IPv6
			item.ObservedAt, item.Observed = cached.AddressesObservedAt, true
			item.Stale = cached.AddressesFailed || time.Since(cached.AddressesObservedAt) > time.Duration(max(interval*2, 180))*time.Second
		}
		result = append(result, item)
	}
	return result, nil
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
