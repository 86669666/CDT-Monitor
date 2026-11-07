package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/runtimeowner"
)

// Recovery is a startup operation, never an incidental effect of opening a DB.
func (s *Store) RecoverInterruptedWork(ctx context.Context, owner *runtimeowner.Owner) error {
	if !owner.Owns(s.dataDir) {
		return errors.New("runtime ownership required")
	}
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
UPDATE jobs SET status='interrupted', error=CASE WHEN error='' THEN 'outcome_unknown: previous runtime interrupted; review required' ELSE error || '; outcome_unknown: previous runtime interrupted; review required' END, updated_at=unixepoch() WHERE status='running';
INSERT INTO logs(type,message,created_at) SELECT 'warning','Notification ' || id || ': delivery_unknown; not resent',unixepoch() FROM notification_outbox WHERE status='sending';
UPDATE notification_outbox SET status='failed', last_error=CASE WHEN last_error='' THEN 'delivery_unknown: previous runtime interrupted; not resent' ELSE last_error || '; delivery_unknown: previous runtime interrupted; not resent' END, updated_at=unixepoch() WHERE status='sending';
UPDATE action_events SET status='uncertain', updated_at=unixepoch() WHERE type='threshold_stop' AND status='attempting';
DELETE FROM scheduler_leases;`)
		return err
	})
}

// Target is immutable evidence for a particular request. Never fill old blank
// targets from today's account configuration.
func ActionTarget(account domain.Account, mode string) string {
	target := struct {
		Credential string `json:"credential_fingerprint"`
		Region     string `json:"region"`
		Instance   string `json:"instance"`
		Action     string `json:"action"`
		Mode       string `json:"shutdown_mode"`
	}{
		fmt.Sprintf("%x", sha256.Sum256([]byte(account.AccessKeyID))), account.RegionID, account.InstanceID, "stop", mode,
	}
	data, _ := json.Marshal(target)
	return string(data)
}

func (s *Store) BeginThresholdStop(ctx context.Context, account domain.Account, mode string) (bool, error) {
	if account.InstanceID == "" {
		return false, errors.New("instance is required")
	}
	res, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO action_events(event_key,account_id,type,status,detail,target,created_at,updated_at) VALUES(?,?,'threshold_stop','attempting','request outcome pending',?,unixepoch(),unixepoch())`, fmt.Sprintf("threshold:%d:stop", account.ID), account.ID, ActionTarget(account, mode))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) SetThresholdOutcome(ctx context.Context, account domain.Account, mode, status string) error {
	if status != "submitted" && status != "uncertain" {
		return errors.New("invalid threshold outcome")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE action_events SET status=?,updated_at=unixepoch() WHERE event_key=? AND target=? AND status='attempting' AND reviewed_at=0`, status, fmt.Sprintf("threshold:%d:stop", account.ID), ActionTarget(account, mode))
	if err != nil {
		return err
	}
	return rowsAffectedOne(res)
}

func (s *Store) ConfirmThresholdStopped(ctx context.Context, account domain.Account, mode string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE action_events SET status='confirmed',detail='same target observed Stopped',updated_at=unixepoch() WHERE event_key=? AND target=? AND status IN ('attempting','submitted','uncertain') AND reviewed_at=0`, fmt.Sprintf("threshold:%d:stop", account.ID), ActionTarget(account, mode))
	return err
}

func (s *Store) ClearConfirmedThreshold(ctx context.Context, account domain.Account, mode string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM action_events WHERE event_key=? AND target=? AND status IN ('confirmed','resolved')`, fmt.Sprintf("threshold:%d:stop", account.ID), ActionTarget(account, mode))
	return err
}

func (s *Store) AutomationBlocked(ctx context.Context, accountID int64, target string) (bool, error) {
	var blocked bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM jobs WHERE status='interrupted' AND reviewed_at=0 AND (account_id=? OR (account_id=0 AND type IN ('monitor_account','refresh_account','control_instance')))) OR EXISTS(SELECT 1 FROM action_events WHERE account_id=? AND type='threshold_stop' AND reviewed_at=0 AND (status IN ('attempting','submitted','uncertain') OR (status='confirmed' AND target<>?)))`, accountID, accountID, target).Scan(&blocked)
	return blocked, err
}

func (s *Store) InterruptJob(ctx context.Context, id, reason string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE jobs SET status='interrupted',error=CASE WHEN error='' THEN ? ELSE error || '; ' || ? END,updated_at=unixepoch() WHERE id=? AND status='running'`, flattenLogMessage(reason), flattenLogMessage(reason), id)
	return err
}

type RecoveryRecord struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	AccountID int64  `json:"account_id"`
	Status    string `json:"status"`
	Detail    string `json:"detail"`
	Target    string `json:"target"`
}

func (s *Store) PendingRecovery(ctx context.Context) ([]RecoveryRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT 'job',id,account_id,status,error,'' FROM jobs WHERE status='interrupted' AND reviewed_at=0 UNION ALL SELECT 'action',event_key,account_id,status,detail,target FROM action_events WHERE type='threshold_stop' AND reviewed_at=0 AND status IN ('attempting','submitted','uncertain','confirmed') UNION ALL SELECT 'notification',id,0,status,last_error,'' FROM notification_outbox WHERE status='failed' AND last_error LIKE '%delivery_unknown%' ORDER BY 1,2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []RecoveryRecord{}
	for rows.Next() {
		var r RecoveryRecord
		if err := rows.Scan(&r.Kind, &r.ID, &r.AccountID, &r.Status, &r.Detail, &r.Target); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	config, err := s.GetConfig(ctx)
	if err != nil {
		return nil, err
	}
	filtered := result[:0]
	for _, r := range result {
		if r.Kind == "action" && r.Status == "confirmed" {
			same := false
			for _, account := range config.Accounts {
				if account.ID == r.AccountID {
					mode := account.ShutdownMode
					if mode == "" {
						mode = config.ShutdownMode
					}
					same = r.Target == ActionTarget(account, mode)
				}
			}
			if same {
				continue
			}
			r.Detail += "; configured target differs; review original target"
		}
		filtered = append(filtered, r)
	}
	return filtered, nil
}

// Resolve only records a human's review. It never dispatches the old payload.
func (s *Store) ResolveRecovery(ctx context.Context, kind, id, note string) error {
	note = strings.TrimSpace(note)
	if note == "" || len([]rune(note)) > 256 || hasTextBreak(note) {
		return errors.New("review note is required (1-256 characters)")
	}
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		var res sql.Result
		var err error
		switch kind {
		case "job":
			res, err = tx.ExecContext(ctx, `UPDATE jobs SET reviewed_at=unixepoch(),unique_key=NULL,updated_at=unixepoch() WHERE id=? AND status='interrupted' AND reviewed_at=0`, id)
		case "action":
			res, err = tx.ExecContext(ctx, `UPDATE action_events SET event_key=?,reviewed_at=unixepoch(),status='resolved',updated_at=unixepoch() WHERE event_key=? AND type='threshold_stop' AND status IN ('attempting','submitted','uncertain','confirmed') AND reviewed_at=0`, fmt.Sprintf("%s:reviewed:%d", id, time.Now().UnixNano()), id)
		default:
			return errors.New("invalid recovery kind")
		}
		if err != nil {
			return err
		}
		if err = rowsAffectedOne(res); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO logs(type,message,created_at) VALUES('audit',?,unixepoch())`, fmt.Sprintf("Recovery reviewed %s %s: %s; no replay", kind, id, note))
		return err
	})
}
