package engine

import (
	"context"
	"errors"
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
