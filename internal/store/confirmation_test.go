package store

import (
	"github.com/wang4386/CDT-Monitor/internal/domain"
	"testing"
)

func TestInstanceActionConfirmationDefaultsAndPersists(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// Existing clients do not send the new setting. It must still default on.
	c := domain.Config{AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "notify_only", APIInterval: 600, Timezone: "Asia/Shanghai"}
	if err := st.Setup(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetConfig(t.Context())
	if err != nil || got.ConfirmInstanceActions == nil || !*got.ConfirmInstanceActions {
		t.Fatal("missing setting did not default to confirmation")
	}
	disabled := false
	got.ConfirmInstanceActions = &disabled
	if err := st.SaveConfig(t.Context(), got); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetConfig(t.Context())
	if got.ConfirmInstanceActions == nil || *got.ConfirmInstanceActions {
		t.Fatal("explicit disable was lost")
	}
	// An older client saving an unrelated setting must not reset the preference.
	got.ConfirmInstanceActions = nil
	got.APIInterval = 300
	if err := st.SaveConfig(t.Context(), got); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetConfig(t.Context())
	if *got.ConfirmInstanceActions || got.APIInterval != 300 {
		t.Fatal("omitted setting overwrote saved preference")
	}
	enabled := true
	got.ConfirmInstanceActions = &enabled
	if err := st.SaveConfig(t.Context(), got); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetConfig(t.Context())
	if !*got.ConfirmInstanceActions {
		t.Fatal("explicit re-enable was lost")
	}
}
