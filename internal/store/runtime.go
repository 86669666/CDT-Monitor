package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/security"
)

func validLogType(logType string) bool {
	switch logType {
	case "info", "warning", "error", "audit", "heartbeat":
		return true
	default:
		return false
	}
}

func (s *Store) AddLog(ctx context.Context, logType, message string) error {
	if !validLogType(logType) {
		return errors.New("log type is invalid")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO logs(type,message,created_at) VALUES(?,?,unixepoch())`, logType, clipRunes(message, maxLogRunes))
	return err
}

func (s *Store) ListLogs(ctx context.Context, tab string, limit int) ([]domain.LogEntry, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	types := []string{"info", "warning", "error", "audit"}
	if tab == "heartbeat" {
		types = []string{"heartbeat"}
	}
	placeholders := "?"
	args := []any{types[0]}
	for _, value := range types[1:] {
		placeholders += ",?"
		args = append(args, value)
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `SELECT id,type,message,created_at FROM logs WHERE type IN (`+placeholders+`) ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := make([]domain.LogEntry, 0)
	for rows.Next() {
		var entry domain.LogEntry
		var created int64
		if err = rows.Scan(&entry.ID, &entry.Type, &entry.Message, &created); err != nil {
			return nil, err
		}
		if entry.ID < 1 {
			return nil, errors.New("log id is invalid")
		}
		if !validLogType(entry.Type) {
			return nil, errors.New("log type is invalid")
		}
		if created <= 0 {
			return nil, errors.New("log timestamp is invalid")
		}
		entry.Message = clipRunes(entry.Message, maxLogRunes)
		entry.CreatedAt = time.Unix(created, 0).UTC()
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (s *Store) ClearLogs(ctx context.Context, tab string) error {
	if tab == "heartbeat" {
		_, err := s.db.ExecContext(ctx, `DELETE FROM logs WHERE type='heartbeat'`)
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM logs WHERE type!='heartbeat'`)
	return err
}

func (s *Store) Prune(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
DELETE FROM logs WHERE (type='heartbeat' AND created_at<unixepoch()-259200) OR (type!='heartbeat' AND created_at<unixepoch()-2592000);
DELETE FROM traffic_hourly WHERE recorded_at<unixepoch()-172800;
DELETE FROM traffic_daily WHERE recorded_at<unixepoch()-5184000;
DELETE FROM billing_cache WHERE updated_at<unixepoch()-7776000;
DELETE FROM sessions WHERE expires_at<unixepoch();
DELETE FROM login_attempts WHERE attempt_time<unixepoch()-86400;
DELETE FROM jobs WHERE status IN ('completed','failed') AND updated_at<unixepoch()-604800;
DELETE FROM notification_outbox WHERE status IN ('sent','failed') AND updated_at<unixepoch()-2592000;
`)
	return err
}

func validTrafficSample(traffic float64) bool {
	return !math.IsNaN(traffic) && !math.IsInf(traffic, 0) && traffic >= 0 && traffic <= maxAccountTrafficGB
}

func validInstanceStatus(status string) bool {
	switch status {
	case domain.StatusUnknown, domain.StatusRunning, domain.StatusStopped, domain.StatusStarting, domain.StatusStopping, "Pending":
		return true
	default:
		return false
	}
}

func (s *Store) AddTrafficStats(ctx context.Context, accountID int64, traffic float64, now time.Time) error {
	if !validTrafficSample(traffic) {
		return errors.New("traffic sample is invalid")
	}
	if !validUnixTime(now) {
		return errors.New("traffic timestamp is invalid")
	}
	if err := s.requireActiveAccount(ctx, accountID); err != nil {
		return err
	}
	hour := now.Truncate(time.Hour).Unix()
	year, month, day := now.Date()
	daily := time.Date(year, month, day, 0, 0, 0, 0, now.Location()).Unix()
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO traffic_hourly(account_id,traffic,recorded_at) VALUES(?,?,?) ON CONFLICT(account_id,recorded_at) DO UPDATE SET traffic=excluded.traffic`, accountID, traffic, hour); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO traffic_daily(account_id,traffic,recorded_at) VALUES(?,?,?) ON CONFLICT(account_id,recorded_at) DO UPDATE SET traffic=excluded.traffic`, accountID, traffic, daily)
		return err
	})
}

func (s *Store) History(ctx context.Context, accountID int64) (domain.History, error) {
	if err := s.requireActiveAccount(ctx, accountID); err != nil {
		return domain.History{}, err
	}
	history := domain.History{Hourly: []domain.TrafficPoint{}, Daily: []domain.TrafficPoint{}}
	queries := []struct {
		sql    string
		target *[]domain.TrafficPoint
	}{
		{`SELECT traffic,recorded_at FROM traffic_hourly WHERE account_id=? ORDER BY recorded_at DESC LIMIT 25`, &history.Hourly},
		{`SELECT traffic,recorded_at FROM traffic_daily WHERE account_id=? ORDER BY recorded_at DESC LIMIT 31`, &history.Daily},
	}
	for _, query := range queries {
		rows, err := s.db.QueryContext(ctx, query.sql, accountID)
		if err != nil {
			return domain.History{}, err
		}
		var reverse []domain.TrafficPoint
		for rows.Next() {
			var point domain.TrafficPoint
			var at int64
			if err = rows.Scan(&point.Traffic, &at); err != nil {
				rows.Close()
				return domain.History{}, err
			}
			if !validTrafficSample(point.Traffic) {
				rows.Close()
				return domain.History{}, errors.New("traffic sample is invalid")
			}
			if at <= 0 {
				rows.Close()
				return domain.History{}, errors.New("traffic timestamp is invalid")
			}
			point.At = time.Unix(at, 0).UTC()
			reverse = append(reverse, point)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return domain.History{}, err
		}
		for index := len(reverse) - 1; index >= 0; index-- {
			*query.target = append(*query.target, reverse[index])
		}
	}
	return history, nil
}

func (s *Store) LastMonitorRun(ctx context.Context) (time.Time, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='last_monitor_run'`).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	unix, err := strconv.ParseInt(value, 10, 64)
	if err != nil || unix <= 0 {
		return time.Time{}, errors.New("last monitor run is invalid")
	}
	return time.Unix(unix, 0).UTC(), nil
}

func (s *Store) SetLastMonitorRun(ctx context.Context, at time.Time) error {
	if at.IsZero() || at.Unix() <= 0 {
		return errors.New("last monitor run is invalid")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES('last_monitor_run',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, strconv.FormatInt(at.Unix(), 10))
	return err
}

const (
	maxJobPayloadRunes   = 4096
	maxJobUniqueKeyRunes = 256
	maxJobTypeRunes      = 64
	maxJobAttempts       = 8
	maxJobIDBytes        = 64
)

func validJobType(jobType string) bool {
	switch jobType {
	case "monitor_account", "refresh_account", "control_instance", "test_notification":
		return true
	default:
		return false
	}
}

func validJobStatus(status string) bool {
	switch status {
	case "queued", "running", "completed", "failed":
		return true
	default:
		return false
	}
}

func validJobPayload(payload string) error {
	if len([]rune(payload)) > maxJobPayloadRunes {
		return errors.New("job payload is too long")
	}
	if !json.Valid([]byte(payload)) {
		return errors.New("job payload is invalid")
	}
	return nil
}

func validateJobAccount(jobType string, accountID int64) error {
	switch jobType {
	case "monitor_account", "refresh_account", "control_instance":
		if accountID < 1 {
			return errors.New("account id is invalid")
		}
	}
	return nil
}

func requireClaimAccount(ctx context.Context, q accountLookup, jobType string, accountID int64) error {
	switch jobType {
	case "monitor_account", "refresh_account", "control_instance":
		if err := requireActiveAccountOn(ctx, q, accountID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errors.New("account id is invalid")
			}
			return err
		}
	}
	return nil
}

func (s *Store) EnqueueJob(ctx context.Context, jobType string, accountID int64, payload, uniqueKey string, maxAttempts int) (domain.Job, error) {
	if jobType == "" || len([]rune(jobType)) > maxJobTypeRunes || !validJobType(jobType) {
		return domain.Job{}, errors.New("job type is invalid")
	}
	if err := validateJobAccount(jobType, accountID); err != nil {
		return domain.Job{}, err
	}
	if maxAttempts < 1 || maxAttempts > maxJobAttempts {
		return domain.Job{}, errors.New("job attempts are invalid")
	}
	if err := validJobPayload(payload); err != nil {
		return domain.Job{}, err
	}
	if len([]rune(uniqueKey)) > maxJobUniqueKeyRunes {
		return domain.Job{}, errors.New("job unique key is too long")
	}
	if uniqueKey != "" && uniqueKey != strings.TrimSpace(uniqueKey) {
		return domain.Job{}, errors.New("job unique key is invalid")
	}
	switch jobType {
	case "monitor_account", "refresh_account", "control_instance":
		if err := s.requireActiveAccount(ctx, accountID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return domain.Job{}, errors.New("account id is invalid")
			}
			return domain.Job{}, err
		}
	}
	id, err := security.NewToken(18)
	if err != nil {
		return domain.Job{}, err
	}
	job := domain.Job{ID: id, Type: jobType, AccountID: accountID, Payload: payload, Status: "queued", MaxAttempts: maxAttempts, AvailableAt: time.Now().UTC(), CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	_, err = s.db.ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,unique_key,status,max_attempts,available_at,created_at,updated_at) VALUES(?,?,?,?,?,'queued',?,?,?,?)`,
		job.ID, job.Type, job.AccountID, job.Payload, nullableString(uniqueKey), job.MaxAttempts, job.AvailableAt.Unix(), job.CreatedAt.Unix(), job.UpdatedAt.Unix())
	if err != nil && uniqueKey != "" {
		var existingID string
		lookupErr := s.db.QueryRowContext(ctx, `SELECT id FROM jobs WHERE unique_key=?`, uniqueKey).Scan(&existingID)
		if lookupErr == nil {
			return s.GetJob(ctx, existingID)
		}
	}
	return job, err
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func validJobID(id string) bool {
	return id != "" && len(id) <= maxJobIDBytes
}

func (s *Store) GetJob(ctx context.Context, id string) (domain.Job, error) {
	if !validJobID(id) {
		return domain.Job{}, sql.ErrNoRows
	}
	var job domain.Job
	var available, created, updated int64
	err := s.db.QueryRowContext(ctx, `SELECT id,type,account_id,payload,status,result,error,attempts,max_attempts,available_at,created_at,updated_at FROM jobs WHERE id=?`, id).
		Scan(&job.ID, &job.Type, &job.AccountID, &job.Payload, &job.Status, &job.Result, &job.Error, &job.Attempts, &job.MaxAttempts, &available, &created, &updated)
	if err != nil {
		return domain.Job{}, err
	}
	if err := validJobPayload(job.Payload); err != nil {
		return domain.Job{}, err
	}
	if !validJobType(job.Type) {
		return domain.Job{}, errors.New("job type is invalid")
	}
	if !validJobStatus(job.Status) {
		return domain.Job{}, errors.New("job status is invalid")
	}
	if err := validateJobAccount(job.Type, job.AccountID); err != nil {
		return domain.Job{}, err
	}
	if available <= 0 || created <= 0 || updated <= 0 {
		return domain.Job{}, errors.New("job timestamp is invalid")
	}
	if err := validRetryBudget(job.Attempts, job.MaxAttempts); err != nil {
		return domain.Job{}, errors.New("job attempts are invalid")
	}
	if err := requireClaimAccount(ctx, s.db, job.Type, job.AccountID); err != nil {
		return domain.Job{}, err
	}
	job.Result = clipRunes(job.Result, maxLogRunes)
	job.Error = clipRunes(job.Error, maxLogRunes)
	job.AvailableAt, job.CreatedAt, job.UpdatedAt = time.Unix(available, 0).UTC(), time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
	return job, nil
}

func (s *Store) ClaimJob(ctx context.Context) (domain.Job, error) {
	var job domain.Job
	var claimErr error
	err := s.WithTx(ctx, func(tx *sql.Tx) error {
		var available, created, updated int64
		err := tx.QueryRowContext(ctx, `SELECT id,type,account_id,payload,status,result,error,attempts,max_attempts,available_at,created_at,updated_at FROM jobs WHERE status='queued' AND available_at<=unixepoch() ORDER BY created_at LIMIT 1`).
			Scan(&job.ID, &job.Type, &job.AccountID, &job.Payload, &job.Status, &job.Result, &job.Error, &job.Attempts, &job.MaxAttempts, &available, &created, &updated)
		if err != nil {
			return err
		}
		if err := validJobPayload(job.Payload); err != nil {
			claimErr = err
		} else if !validJobType(job.Type) {
			claimErr = errors.New("job type is invalid")
		} else if job.Status != "queued" || !validJobStatus(job.Status) {
			claimErr = errors.New("job status is invalid")
		} else if err := validateJobAccount(job.Type, job.AccountID); err != nil {
			claimErr = err
		} else if available <= 0 || created <= 0 || updated <= 0 {
			claimErr = errors.New("job timestamp is invalid")
		} else if err := validRetryBudget(job.Attempts, job.MaxAttempts); err != nil {
			claimErr = errors.New("job attempts are invalid")
		} else if err := requireClaimAccount(ctx, tx, job.Type, job.AccountID); err != nil {
			if err.Error() == "account id is invalid" {
				claimErr = err
			} else {
				return err
			}
		}
		if claimErr != nil {
			if _, failErr := tx.ExecContext(ctx, `UPDATE jobs SET status='failed',error=?,unique_key=NULL,updated_at=unixepoch() WHERE id=? AND status='queued'`, claimErr.Error(), job.ID); failErr != nil {
				return failErr
			}
			return nil
		}
		result, err := tx.ExecContext(ctx, `UPDATE jobs SET status='running',locked_at=unixepoch(),attempts=attempts+1,updated_at=unixepoch() WHERE id=? AND status='queued'`, job.ID)
		if err != nil {
			return err
		}
		if err = rowsAffectedOne(result); err != nil {
			return err
		}
		job.Status, job.Attempts = "running", job.Attempts+1
		job.AvailableAt, job.CreatedAt, job.UpdatedAt = time.Unix(available, 0).UTC(), time.Unix(created, 0).UTC(), time.Now().UTC()
		return nil
	})
	if err != nil {
		return domain.Job{}, err
	}
	if claimErr != nil {
		return domain.Job{}, claimErr
	}
	return job, nil
}

func rowsAffectedOne(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) CompleteJob(ctx context.Context, id, result string) error {
	if !validJobID(id) {
		return sql.ErrNoRows
	}
	res, err := s.db.ExecContext(ctx, `UPDATE jobs SET status='completed',result=?,error='',unique_key=CASE WHEN type='monitor_account' THEN unique_key ELSE NULL END,updated_at=unixepoch() WHERE id=?`, clipRunes(result, maxLogRunes), id)
	if err != nil {
		return err
	}
	return rowsAffectedOne(res)
}

func validRetryBudget(attempts, maxAttempts int) error {
	if attempts < 0 || maxAttempts < 1 {
		return errors.New("attempts are invalid")
	}
	return nil
}

func (s *Store) FailJob(ctx context.Context, job domain.Job, jobErr error) error {
	if !validJobID(job.ID) {
		return sql.ErrNoRows
	}
	if jobErr == nil {
		return errors.New("job error is required")
	}
	if err := validRetryBudget(job.Attempts, job.MaxAttempts); err != nil {
		return errors.New("job attempts are invalid")
	}
	status := "failed"
	available := time.Now().UTC()
	if job.Attempts < job.MaxAttempts {
		status = "queued"
		delay := time.Duration(1<<min(job.Attempts, 6)) * time.Second
		available = available.Add(delay)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE jobs SET status=?,error=?,available_at=?,unique_key=CASE WHEN ?='failed' THEN NULL ELSE unique_key END,updated_at=unixepoch() WHERE id=?`, status, clipRunes(jobErr.Error(), maxLogRunes), available.Unix(), status, job.ID)
	if err != nil {
		return err
	}
	return rowsAffectedOne(res)
}

const (
	maxLeaseNameRunes  = 64
	maxLeaseOwnerRunes = 128
)

func validLeaseIdentity(value string, max int) bool {
	return value != "" && value == strings.TrimSpace(value) && len([]rune(value)) <= max
}

func (s *Store) AcquireLease(ctx context.Context, name, owner string, ttl time.Duration) (bool, error) {
	if !validLeaseIdentity(name, maxLeaseNameRunes) || !validLeaseIdentity(owner, maxLeaseOwnerRunes) {
		return false, errors.New("lease identity is invalid")
	}
	if ttl <= 0 {
		return false, errors.New("lease ttl is invalid")
	}
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `INSERT INTO scheduler_leases(name,owner,expires_at,updated_at) VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at,updated_at=excluded.updated_at WHERE scheduler_leases.expires_at<? OR scheduler_leases.owner=?`,
		name, owner, now.Add(ttl).Unix(), now.Unix(), now.Unix(), owner)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if count == 1 {
		return true, nil
	}
	// A same-owner refresh in the same unix second can be a no-op write.
	var current string
	var expires int64
	err = s.db.QueryRowContext(ctx, `SELECT owner, expires_at FROM scheduler_leases WHERE name=?`, name).Scan(&current, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !validLeaseIdentity(current, maxLeaseOwnerRunes) {
		return false, errors.New("lease identity is invalid")
	}
	return current == owner && expires >= now.Unix(), nil
}

const (
	maxActionEventKeyRunes    = 128
	maxActionEventDetailRunes = 256
)

func validActionEventType(eventType string) bool {
	switch eventType {
	case "threshold", "threshold_stop", "keepalive", "schedule_start", "schedule_stop":
		return true
	default:
		return false
	}
}

func validActionEventStatus(status string) bool {
	switch status {
	case "attempting", "detected":
		return true
	default:
		return false
	}
}

func (s *Store) RecordActionEvent(ctx context.Context, key string, accountID int64, eventType, status, detail string) (bool, error) {
	if key == "" || len([]rune(key)) > maxActionEventKeyRunes {
		return false, errors.New("action event key is invalid")
	}
	if !validActionEventType(eventType) || !validActionEventStatus(status) {
		return false, errors.New("action event type is invalid")
	}
	if err := s.requireActiveAccount(ctx, accountID); err != nil {
		return false, err
	}
	detail = clipRunes(detail, maxActionEventDetailRunes)
	result, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO action_events(event_key,account_id,type,status,detail,created_at,updated_at) VALUES(?,?,?,?,?,unixepoch(),unixepoch())`, key, accountID, eventType, status, detail)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return count == 1, nil
}

func (s *Store) DeleteActionEvent(ctx context.Context, key string) error {
	if key == "" || len([]rune(key)) > maxActionEventKeyRunes {
		return errors.New("action event key is invalid")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM action_events WHERE event_key=?`, key)
	return err
}

const (
	maxOutboxPayloadRunes       = 8192
	maxOutboxEventIDRunes       = 64
	maxOutboxChannels           = 3
	maxOutboxIDBytes            = 128
	maxNotificationTitleRunes   = 128
	maxNotificationSummaryRunes = 1024
	maxNotificationFields       = 16
	maxNotificationFieldRunes   = 128
)

func validOutboxChannel(channel string) bool {
	switch channel {
	case "email", "telegram", "webhook":
		return true
	default:
		return false
	}
}

func validNotificationEventType(eventType string) bool {
	switch eventType {
	case "test", "threshold", "keepalive", "schedule":
		return true
	default:
		return false
	}
}

func validateNotificationEvent(event domain.NotificationEvent) error {
	if !validNotificationEventType(event.Type) {
		return errors.New("notification event type is invalid")
	}
	if len([]rune(event.Title)) > maxNotificationTitleRunes || len([]rune(event.Summary)) > maxNotificationSummaryRunes {
		return errors.New("notification event is too long")
	}
	if len(event.Fields) > maxNotificationFields {
		return errors.New("notification event is too long")
	}
	for key, value := range event.Fields {
		if len([]rune(key)) > maxNotificationFieldRunes || len([]rune(value)) > maxNotificationFieldRunes {
			return errors.New("notification event is too long")
		}
	}
	return nil
}

func ValidateOutboxItem(channel string, event domain.NotificationEvent) error {
	if event.ID == "" || len([]rune(event.ID)) > maxOutboxEventIDRunes {
		return errors.New("notification event id is invalid")
	}
	if !validOutboxChannel(channel) {
		return errors.New("notification channel is invalid")
	}
	return validateNotificationEvent(event)
}

func (s *Store) AddOutbox(ctx context.Context, event domain.NotificationEvent, channels []string) error {
	if event.ID == "" || len([]rune(event.ID)) > maxOutboxEventIDRunes {
		return errors.New("notification event id is invalid")
	}
	if err := validateNotificationEvent(event); err != nil {
		return err
	}
	if len(channels) > maxOutboxChannels {
		return errors.New("too many notification channels")
	}
	for _, channel := range channels {
		if !validOutboxChannel(channel) {
			return errors.New("notification channel is invalid")
		}
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(payload) > maxOutboxPayloadRunes {
		return errors.New("notification payload is too long")
	}
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		for _, channel := range channels {
			id := event.ID + ":" + channel
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO notification_outbox(id,event_id,channel,payload,status,available_at,created_at,updated_at) VALUES(?,?,?,?,'queued',unixepoch(),unixepoch(),unixepoch())`, id, event.ID, channel, string(payload)); err != nil {
				return err
			}
		}
		return nil
	})
}

type OutboxItem struct {
	ID, Channel, Payload  string
	Attempts, MaxAttempts int
}

func (s *Store) ClaimOutbox(ctx context.Context) (OutboxItem, error) {
	var item OutboxItem
	var claimErr error
	err := s.WithTx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT id,channel,payload,attempts,max_attempts FROM notification_outbox WHERE status='queued' AND available_at<=unixepoch() ORDER BY created_at LIMIT 1`).Scan(&item.ID, &item.Channel, &item.Payload, &item.Attempts, &item.MaxAttempts); err != nil {
			return err
		}
		if len(item.Payload) > maxOutboxPayloadRunes {
			claimErr = errors.New("notification payload is too long")
		} else if err := validRetryBudget(item.Attempts, item.MaxAttempts); err != nil {
			claimErr = errors.New("outbox attempts are invalid")
		} else {
			var event domain.NotificationEvent
			if err := json.Unmarshal([]byte(item.Payload), &event); err != nil {
				claimErr = errors.New("notification payload is invalid")
			} else {
				claimErr = ValidateOutboxItem(item.Channel, event)
			}
		}
		if claimErr != nil {
			if _, failErr := tx.ExecContext(ctx, `UPDATE notification_outbox SET status='failed',last_error=?,updated_at=unixepoch() WHERE id=? AND status='queued'`, claimErr.Error(), item.ID); failErr != nil {
				return failErr
			}
			return nil
		}
		result, err := tx.ExecContext(ctx, `UPDATE notification_outbox SET status='sending',attempts=attempts+1,updated_at=unixepoch() WHERE id=? AND status='queued'`, item.ID)
		if err != nil {
			return err
		}
		if err = rowsAffectedOne(result); err != nil {
			return err
		}
		item.Attempts++
		return nil
	})
	if err != nil {
		return OutboxItem{}, err
	}
	if claimErr != nil {
		return OutboxItem{}, claimErr
	}
	return item, nil
}

func validOutboxID(id string) bool {
	return id != "" && len(id) <= maxOutboxIDBytes
}

func (s *Store) CompleteOutbox(ctx context.Context, id string) error {
	if !validOutboxID(id) {
		return sql.ErrNoRows
	}
	res, err := s.db.ExecContext(ctx, `UPDATE notification_outbox SET status='sent',last_error='',updated_at=unixepoch() WHERE id=?`, id)
	if err != nil {
		return err
	}
	return rowsAffectedOne(res)
}

func (s *Store) FailOutbox(ctx context.Context, item OutboxItem, sendErr error) error {
	if !validOutboxID(item.ID) {
		return sql.ErrNoRows
	}
	if sendErr == nil {
		return errors.New("outbox error is required")
	}
	if err := validRetryBudget(item.Attempts, item.MaxAttempts); err != nil {
		return errors.New("outbox attempts are invalid")
	}
	status := "failed"
	available := time.Now().UTC()
	if item.Attempts < item.MaxAttempts {
		status = "queued"
		available = available.Add(time.Duration(1<<min(item.Attempts, 7)) * time.Second)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE notification_outbox SET status=?,last_error=?,available_at=?,updated_at=unixepoch() WHERE id=?`, status, clipRunes(sendErr.Error(), maxLogRunes), available.Unix(), item.ID)
	if err != nil {
		return err
	}
	return rowsAffectedOne(res)
}

const maxBillingCacheBytes = 8192

func validBillingCacheType(cacheType string) bool {
	switch cacheType {
	case "balance", "instance_bill", "error":
		return true
	default:
		return false
	}
}

func validBillingCycle(cycle string) bool {
	if cycle == "" {
		return true
	}
	if len(cycle) != 7 {
		return false
	}
	_, err := time.Parse("2006-01", cycle)
	return err == nil
}

func (s *Store) BillingCache(ctx context.Context, accountID int64, cacheType, cycle string, maxAge time.Duration, target any) (bool, error) {
	if !validBillingCacheType(cacheType) || !validBillingCycle(cycle) {
		return false, errors.New("billing cache key is invalid")
	}
	if err := s.requireActiveAccount(ctx, accountID); err != nil {
		return false, err
	}
	var data string
	var updated int64
	err := s.db.QueryRowContext(ctx, `SELECT data,updated_at FROM billing_cache WHERE account_id=? AND cache_type=? AND billing_cycle=?`, accountID, cacheType, cycle).Scan(&data, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if updated <= 0 {
		return false, errors.New("billing cache timestamp is invalid")
	}
	if time.Since(time.Unix(updated, 0).UTC()) > maxAge {
		return false, nil
	}
	if len(data) > maxBillingCacheBytes {
		return false, errors.New("billing cache payload is too long")
	}
	return true, json.Unmarshal([]byte(data), target)
}

func (s *Store) SetBillingCache(ctx context.Context, accountID int64, cacheType, cycle string, value any) error {
	if !validAccountID(accountID) {
		return sql.ErrNoRows
	}
	if !validBillingCacheType(cacheType) || !validBillingCycle(cycle) {
		return errors.New("billing cache key is invalid")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > maxBillingCacheBytes {
		return errors.New("billing cache payload is too long")
	}
	if err = s.requireActiveAccount(ctx, accountID); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO billing_cache(account_id,cache_type,billing_cycle,data,updated_at) VALUES(?,?,?,?,unixepoch()) ON CONFLICT(account_id,cache_type,billing_cycle) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at`, accountID, cacheType, cycle, string(data))
	return err
}

func (s *Store) CountQueuedJobs(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')`).Scan(&count)
	return count, err
}

func (s *Store) DebugStats(ctx context.Context) (map[string]int, error) {
	result := map[string]int{}
	for _, table := range []string{"accounts", "logs", "jobs", "notification_outbox", "api_keys"} {
		var count int
		if err := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count); err != nil {
			return nil, err
		}
		result[table] = count
	}
	return result, nil
}
