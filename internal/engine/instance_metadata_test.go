package engine

import (
	"context"
	"errors"
	"github.com/wang4386/CDT-Monitor/internal/aliyun"
	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/notify"
	"testing"
	"time"
)

type metadataProvider struct {
	*fakeProvider
	kind string
	err  error
}

type detailsProvider struct {
	*fakeProvider
	details aliyun.InstanceDetails
	err     error
	calls   int
}

func (p *detailsProvider) GetInstanceMetadata(context.Context, domain.Account, string) (aliyun.InstanceDetails, error) {
	p.calls++
	return p.details, p.err
}

func TestInstanceAddressCacheIdentityAndFreshness(t *testing.T) {
	st, a := setupAccount(t, func(c *domain.Config) { c.EnableBilling = false; c.KeepAlive = false })
	defer st.Close()
	ctx := context.Background()
	p := &detailsProvider{fakeProvider: newFakeProvider(), details: aliyun.InstanceDetails{ChargeType: "spot", PublicIPv4: "203.0.113.7", IPv6: "2001:db8::1"}}
	e := New(st, p, notify.New(), quietLogger(), 1)
	// Old cache formats carry a purchase observation but no address observation.
	if err := st.SetBillingCache(ctx, a.ID, "instance_metadata", "", map[string]any{"identity": instanceMetadataIdentity(a), "kind": "spot", "observed_at": time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	rows, err := e.InstanceAddresses(ctx)
	if err != nil || len(rows) != 1 || rows[0].Observed || !rows[0].Stale {
		t.Fatalf("legacy address state: %+v %v", rows, err)
	}
	if _, err = e.processAccount(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	rows, _ = e.InstanceAddresses(ctx)
	if !rows[0].Observed || rows[0].Stale || rows[0].PublicIPv4 != "203.0.113.7" || rows[0].IPv6 != "2001:db8::1" || p.calls != 1 {
		t.Fatalf("fresh state: %+v calls=%d", rows, p.calls)
	}
	p.err = errors.New("unavailable")
	if _, err = e.processAccount(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	rows, _ = e.InstanceAddresses(ctx)
	if !rows[0].Stale || rows[0].PublicIPv4 != "203.0.113.7" {
		t.Fatalf("failure did not retain stale address: %+v", rows)
	}
	p.err, p.details.PublicIPv4, p.details.IPv6 = nil, "", ""
	if _, err = e.processAccount(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	rows, _ = e.InstanceAddresses(ctx)
	if rows[0].Stale || !rows[0].Observed || rows[0].PublicIPv4 != "" || rows[0].IPv6 != "" {
		t.Fatalf("empty success did not clear addresses: %+v", rows)
	}
	config, _ := st.GetConfig(ctx)
	config.Accounts[0].InstanceID = "i-replaced"
	if err = st.SaveConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
	if err = st.SetBillingCache(ctx, a.ID, "instance_metadata", "", instanceMetadata{Identity: instanceMetadataIdentity(a), Kind: "spot", PublicIPv4: "203.0.113.7", AddressesObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	rows, _ = e.InstanceAddresses(ctx)
	if rows[0].Observed || rows[0].PublicIPv4 != "" || rows[0].InstanceID != "i-replaced" {
		t.Fatalf("old identity leaked: %+v", rows)
	}
	config.Accounts[0].InstanceID = ""
	if err = st.SaveConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
	before := p.calls
	if _, err = e.processAccount(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	rows, _ = e.InstanceAddresses(ctx)
	if len(rows) != 0 || p.calls != before || len(p.controlActions()) != 0 {
		t.Fatal("unbound account queried details or performed control")
	}
}

func (p *metadataProvider) GetInstanceChargeType(context.Context, domain.Account, string) (string, error) {
	return p.kind, p.err
}

func TestMetadataIndependentOfBillingAndIdentityBound(t *testing.T) {
	st, a := setupAccount(t, func(c *domain.Config) {
		c.EnableBilling = false
		c.ThresholdAction = "notify_only"
		c.KeepAlive = false
	})
	defer st.Close()
	ctx := context.Background()
	p := &metadataProvider{fakeProvider: newFakeProvider(), kind: "subscription"}
	e := New(st, p, notify.New(), quietLogger(), 1)
	if _, err := e.processAccount(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	rows, _, err := e.Summary(ctx)
	if err != nil || rows[0].InstanceChargeType != "subscription" || rows[0].InstanceTypeStale {
		t.Fatalf("metadata missing %+v %v", rows, err)
	}
	p.err = errors.New("permission denied")
	if _, err := e.processAccount(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	rows, _, _ = e.Summary(ctx)
	if rows[0].InstanceChargeType != "subscription" || !rows[0].InstanceTypeStale {
		t.Fatal("failed refresh lost stale indication")
	}
	c, _ := st.GetConfig(ctx)
	c.Accounts[0].InstanceID = "i-replaced"
	if err := st.SaveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	// Simulate a late request for the previous instance completing after the edit.
	if err := st.SetBillingCache(ctx, a.ID, "instance_metadata", "", instanceMetadata{Identity: instanceMetadataIdentity(a), Kind: "spot", ObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	rows, _, _ = e.Summary(ctx)
	if rows[0].InstanceChargeType != "unknown" || !rows[0].InstanceTypeStale {
		t.Fatal("old identity contaminated new target")
	}
	if len(p.controlActions()) != 0 {
		t.Fatal("display metadata caused cloud mutation")
	}
}
