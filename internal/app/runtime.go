package app

import (
	"context"
	"errors"
	"github.com/wang4386/CDT-Monitor/internal/runtimeowner"
	"github.com/wang4386/CDT-Monitor/internal/store"
)

// DataRuntime owns migrations, startup recovery and the entire worker lifetime.
// The caller must stop and join workers before Close.
type DataRuntime struct {
	Store *store.Store
	owner *runtimeowner.Owner
}

func OpenData(dataDir string, recoverWork bool) (*DataRuntime, error) {
	owner, err := runtimeowner.Acquire(dataDir)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(dataDir)
	if err != nil {
		owner.Close()
		return nil, err
	}
	if recoverWork {
		if err = st.RecoverInterruptedWork(context.Background(), owner); err != nil {
			st.Close()
			owner.Close()
			return nil, err
		}
	}
	return &DataRuntime{Store: st, owner: owner}, nil
}

func (r *DataRuntime) Close() error { return errors.Join(r.Store.Close(), r.owner.Close()) }
