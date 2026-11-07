package engine

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/wang4386/CDT-Monitor/internal/domain"
)

var errControlOutcomeUnknown = errors.New("control outcome unknown; review required")

// The provider has no durable request-ID/status contract. Once called, neither
// an error nor a panic proves that the cloud did not accept the operation.
func (e *Engine) callControl(ctx context.Context, account domain.Account, secret, action, mode string) (err error) {
	defer func() {
		if recover() != nil {
			err = errControlOutcomeUnknown
		}
	}()
	if cause := e.provider.ControlInstance(ctx, account, secret, action, mode); cause != nil {
		return fmt.Errorf("%w: %v", errControlOutcomeUnknown, providerError(cause, account.AccessKeyID, secret))
	}
	return nil
}

func (e *Engine) ResolveRecovery(ctx context.Context, kind, id, note string) error {
	records, err := e.store.PendingRecovery(ctx)
	if err != nil {
		return err
	}
	for _, r := range records {
		if r.Kind == kind && r.ID == id {
			lock := e.accountLock(r.AccountID)
			lock.Lock()
			defer lock.Unlock()
			return e.store.ResolveRecovery(ctx, kind, id, e.persistRedacted(ctx, note))
		}
	}
	return sql.ErrNoRows
}
