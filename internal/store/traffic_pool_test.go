package store

import (
	"context"
	"testing"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/domain"
)

func TestPoolQuotaValidationAndIdentityReset(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	c := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "notify_only", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{
		{AccessKeyID: "LTAIshared", AccessKeySecret: "test-secret", RegionID: "cn-beijing", InstanceID: "i-one", MaxTraffic: 20},
		{AccessKeyID: "LTAIshared", AccessKeySecret: "test-secret", RegionID: "cn-shanghai", InstanceID: "i-two", MaxTraffic: 20},
	}}
	if err := st.Setup(ctx, c); err != nil {
		t.Fatal(err)
	}
	c, _ = st.GetConfig(ctx)
	c.Accounts[0].MaxTraffic = 25
	if err := st.SaveConfig(ctx, c); err == nil {
		t.Fatal("different quotas in same pool accepted")
	}
	saved, _ := st.GetConfig(ctx)
	if saved.Accounts[0].MaxTraffic != 20 {
		t.Fatal("partial write on rejected save")
	}
	c = saved
	at := time.Now().UTC().Truncate(time.Second)
	if err := st.UpdateRuntime(ctx, c.Accounts[0].ID, 18, domain.StatusRunning, at); err != nil {
		t.Fatal(err)
	}
	oldIdentity := c.Accounts[0]
	c.Accounts[0].RegionID, c.Accounts[0].MaxTraffic = "cn-hongkong", 200
	if err := st.SaveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateRuntimeForAccount(ctx, oldIdentity, 19, domain.StatusRunning, time.Now()); err == nil {
		t.Fatal("in-flight old-pool response accepted after identity changed")
	}
	if err := st.UpdateInstanceStatusForAccount(ctx, oldIdentity, domain.StatusStopped); err == nil {
		t.Fatal("old target status accepted after identity changed")
	}
	a, _ := st.GetAccount(ctx, c.Accounts[0].ID)
	if a.TrafficUsed != 0 || !a.UpdatedAt.IsZero() {
		t.Fatal("old domestic sample leaked into international pool")
	}
	if err := st.UpdateRuntime(ctx, a.ID, 8, domain.StatusRunning, at); err != nil {
		t.Fatal(err)
	}
	c, _ = st.GetConfig(ctx)
	c.Accounts[0].AccessKeyID, c.Accounts[0].AccessKeySecret = "LTAIanother", "new-test-secret"
	if err := st.SaveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	a, _ = st.GetAccount(ctx, a.ID)
	if a.TrafficUsed != 0 || !a.UpdatedAt.IsZero() {
		t.Fatal("old credential sample retained")
	}
}

func TestLegacyPoolConflictRemainsReadable(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	insertTestAccount(t, st, 1)
	insertTestAccount(t, st, 2)
	if _, err := st.db.Exec(`UPDATE accounts SET access_key_id='LTAIshared',max_traffic=CASE id WHEN 1 THEN 20 ELSE 30 END`); err != nil {
		t.Fatal(err)
	}
	c, err := st.GetConfig(context.Background())
	if err != nil {
		t.Fatal("legacy conflict must remain editable:", err)
	}
	if !domain.ConflictingTrafficPools(c.Accounts)[domain.TrafficPoolID(c.Accounts[0])] {
		t.Fatal("conflict not detected")
	}
}
