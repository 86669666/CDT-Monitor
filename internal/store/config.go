package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/notify"
	"github.com/wang4386/CDT-Monitor/internal/security"
)

const (
	minAPIIntervalSeconds   = 30
	maxAccountRemarkRunes   = 64
	maxAccessKeyIDRunes     = 64
	maxRegionIDRunes        = 32
	maxInstanceIDRunes      = 64
	maxAccessKeySecretRunes = 128
	maxAccountTrafficGB     = 1000000
	maxAccounts             = 32
	maxTimezoneRunes        = 64
	maxSettingKeyRunes      = 64
	maxSettingValueBytes    = 32 << 10
)

var sensitiveSettings = map[string]bool{
	"notify_password":      true,
	"notify_tg_token":      true,
	"notify_tg_proxy_pass": true,
	"notify_wh_headers":    true,
	"notify_wh_secret":     true,
	"notify_wh_url":        true,
	"notify_wh_body":       true,
	"notify_tg_proxy_url":  true,
}

func boolSetting(settings map[string]string, key string, fallback bool) bool {
	value, ok := settings[key]
	if !ok {
		return fallback
	}
	return value == "1" || strings.EqualFold(value, "true")
}

func intSetting(settings map[string]string, key string, fallback int) (int, error) {
	value, ok := settings[key]
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("setting %s is invalid", key)
	}
	return parsed, nil
}

func (s *Store) getSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	settings := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err = rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		if len([]rune(key)) > maxSettingKeyRunes || len(value) > maxSettingValueBytes {
			return nil, errors.New("setting is too large")
		}
		if sensitiveSettings[key] {
			value, err = s.DecryptAAD(value, key)
			if err != nil {
				return nil, fmt.Errorf("decrypt setting %s: %w", key, err)
			}
		}
		settings[key] = value
	}
	return settings, rows.Err()
}

func (s *Store) GetConfig(ctx context.Context) (domain.Config, error) {
	settings, err := s.getSettings(ctx)
	if err != nil {
		return domain.Config{}, err
	}
	accounts, err := s.ListAccounts(ctx)
	if err != nil {
		return domain.Config{}, err
	}
	if accounts == nil {
		accounts = []domain.Account{}
	}
	apiInterval, err := intSetting(settings, "api_interval", 600)
	if err != nil {
		return domain.Config{}, err
	}
	if apiInterval < minAPIIntervalSeconds {
		apiInterval = minAPIIntervalSeconds
	}
	if apiInterval > 86400 {
		return domain.Config{}, errors.New("api interval must be between 30 and 86400 seconds")
	}
	trafficThreshold, err := intSetting(settings, "traffic_threshold", 95)
	if err != nil {
		return domain.Config{}, err
	}
	if trafficThreshold < 1 || trafficThreshold > 100 {
		return domain.Config{}, errors.New("traffic threshold must be between 1 and 100")
	}
	notifyPort, err := intSetting(settings, "notify_port", 465)
	if err != nil {
		return domain.Config{}, err
	}
	if err = notify.ValidateTCPPort(notifyPort); err != nil {
		return domain.Config{}, err
	}
	shutdownMode := valueOr(settings, "shutdown_mode", "KeepCharging")
	if shutdownMode != "KeepCharging" && shutdownMode != "StopCharging" {
		return domain.Config{}, errors.New("invalid shutdown mode")
	}
	thresholdAction := valueOr(settings, "threshold_action", "stop_and_notify")
	if thresholdAction != "stop_and_notify" && thresholdAction != "notify_only" {
		return domain.Config{}, errors.New("invalid threshold action")
	}
	timezone := valueOr(settings, "timezone", "Asia/Shanghai")
	if len([]rune(timezone)) > maxTimezoneRunes {
		return domain.Config{}, errors.New("invalid timezone")
	}
	if _, err = time.LoadLocation(timezone); err != nil {
		return domain.Config{}, errors.New("invalid timezone")
	}
	config := domain.Config{
		TrafficThreshold:   trafficThreshold,
		EnableScheduleMail: boolSetting(settings, "enable_schedule_email", false),
		ShutdownMode:       shutdownMode,
		ThresholdAction:    thresholdAction,
		KeepAlive:          boolSetting(settings, "keep_alive", false),
		APIInterval:        apiInterval,
		EnableBilling:      boolSetting(settings, "enable_billing", false),
		Timezone:           timezone,
		Accounts:           accounts,
		Notifications: domain.NotificationConfig{
			Email: domain.EmailConfig{
				Enabled:            boolSetting(settings, "notify_email_enabled", true),
				To:                 valueOr(settings, "notify_email", ""),
				Host:               valueOr(settings, "notify_host", ""),
				Port:               notifyPort,
				Username:           valueOr(settings, "notify_username", ""),
				Password:           valueOr(settings, "notify_password", ""),
				PasswordConfigured: settings["notify_password"] != "",
				Security:           valueOr(settings, "notify_secure", "ssl"),
			},
			Telegram: domain.TelegramConfig{
				Enabled:            boolSetting(settings, "notify_tg_enabled", false),
				Token:              valueOr(settings, "notify_tg_token", ""),
				TokenConfigured:    settings["notify_tg_token"] != "",
				ChatID:             valueOr(settings, "notify_tg_chat_id", ""),
				ProxyType:          valueOr(settings, "notify_tg_proxy_type", "none"),
				ProxyURL:           valueOr(settings, "notify_tg_proxy_url", ""),
				ProxyURLConfigured: settings["notify_tg_proxy_url"] != "",
				ProxyIP:            valueOr(settings, "notify_tg_proxy_ip", ""),
				ProxyPort:          valueOr(settings, "notify_tg_proxy_port", ""),
				ProxyUser:          valueOr(settings, "notify_tg_proxy_user", ""),
				ProxyPass:          valueOr(settings, "notify_tg_proxy_pass", ""),
				ProxyConfigured:    settings["notify_tg_proxy_pass"] != "",
			},
			Webhook: domain.WebhookConfig{
				Enabled:           boolSetting(settings, "notify_wh_enabled", false),
				URL:               valueOr(settings, "notify_wh_url", ""),
				Method:            valueOr(settings, "notify_wh_method", "GET"),
				Type:              valueOr(settings, "notify_wh_request_type", "JSON"),
				Headers:           valueOr(settings, "notify_wh_headers", ""),
				Body:              valueOr(settings, "notify_wh_body", ""),
				Provider:          valueOr(settings, "notify_wh_provider", "generic"),
				Secret:            valueOr(settings, "notify_wh_secret", ""),
				SecretConfigured:  settings["notify_wh_secret"] != "",
				HeadersConfigured: settings["notify_wh_headers"] != "",
				URLConfigured:     settings["notify_wh_url"] != "",
				BodyConfigured:    settings["notify_wh_body"] != "",
			},
		},
	}
	if err = notify.ValidateNotifyOptions(config.Notifications); err != nil {
		return domain.Config{}, err
	}
	return config, nil
}

func valueOr(values map[string]string, key, fallback string) string {
	if value, ok := values[key]; ok && value != "" {
		return value
	}
	return fallback
}

func (s *Store) IsInitialized(ctx context.Context) (bool, error) {
	var password string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='admin_password'`).Scan(&password)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil && password != "", err
}

func (s *Store) Setup(ctx context.Context, config domain.Config) error {
	initialized, err := s.IsInitialized(ctx)
	if err != nil {
		return err
	}
	if initialized {
		return errors.New("system is already initialized")
	}
	return s.saveConfig(ctx, config, true)
}

func (s *Store) SaveConfig(ctx context.Context, config domain.Config) error {
	return s.saveConfig(ctx, config, false)
}

func (s *Store) saveConfig(ctx context.Context, config domain.Config, setup bool) error {
	if config.TrafficThreshold < 1 || config.TrafficThreshold > 100 {
		return errors.New("traffic threshold must be between 1 and 100")
	}
	if config.ShutdownMode != "KeepCharging" && config.ShutdownMode != "StopCharging" {
		return errors.New("invalid shutdown mode")
	}
	if config.ThresholdAction != "stop_and_notify" && config.ThresholdAction != "notify_only" {
		return errors.New("invalid threshold action")
	}
	if config.APIInterval < minAPIIntervalSeconds || config.APIInterval > 86400 {
		return errors.New("api interval must be between 30 and 86400 seconds")
	}
	if config.Timezone == "" {
		config.Timezone = "Asia/Shanghai"
	}
	if len([]rune(config.Timezone)) > maxTimezoneRunes {
		return errors.New("invalid timezone")
	}
	if _, err := time.LoadLocation(config.Timezone); err != nil {
		return errors.New("invalid timezone")
	}
	if setup && len(config.AdminPassword) < 10 {
		return errors.New("administrator password must be at least 10 characters")
	}
	if err := notify.ValidateCallbackURL(config.Notifications.Webhook.URL); err != nil {
		return err
	}
	if err := notify.ValidateProxyURL(config.Notifications.Telegram.ProxyURL); err != nil {
		return err
	}
	if err := notify.ValidateDialHost(config.Notifications.Telegram.ProxyIP); err != nil {
		return err
	}
	if err := notify.ValidateDialHost(config.Notifications.Email.Host); err != nil {
		return err
	}
	if err := notify.ValidateSMTPIdentity(config.Notifications.Email.Username, config.Notifications.Email.To); err != nil {
		return err
	}
	if err := notify.ValidateTelegramChatID(config.Notifications.Telegram.ChatID); err != nil {
		return err
	}
	if err := notify.ValidateWebhookHeaders(config.Notifications.Webhook.Headers); err != nil {
		return err
	}
	if err := notify.ValidateWebhookBody(config.Notifications.Webhook.Body); err != nil {
		return err
	}
	if err := notify.ValidateTCPPort(config.Notifications.Email.Port); err != nil {
		return err
	}
	if err := notify.ValidateTCPPortString(config.Notifications.Telegram.ProxyPort); err != nil {
		return err
	}
	if err := notify.ValidateNotifyOptions(config.Notifications); err != nil {
		return err
	}
	if err := notify.ValidateNotifyCredentials(config.Notifications); err != nil {
		return err
	}
	if len(config.Accounts) > maxAccounts {
		return errors.New("too many accounts")
	}

	return s.WithTx(ctx, func(tx *sql.Tx) error {
		if config.AdminPassword != "" {
			hash, err := hashOrKeepPassword(config.AdminPassword)
			if err != nil {
				return err
			}
			if err = putSettingTx(ctx, tx, "admin_password", hash); err != nil {
				return err
			}
		} else if setup {
			return errors.New("administrator password is required")
		}

		values := map[string]string{
			"traffic_threshold":      strconv.Itoa(config.TrafficThreshold),
			"enable_schedule_email":  strconv.FormatBool(config.EnableScheduleMail),
			"shutdown_mode":          config.ShutdownMode,
			"threshold_action":       config.ThresholdAction,
			"keep_alive":             strconv.FormatBool(config.KeepAlive),
			"api_interval":           strconv.Itoa(config.APIInterval),
			"enable_billing":         strconv.FormatBool(config.EnableBilling),
			"timezone":               config.Timezone,
			"notify_email_enabled":   strconv.FormatBool(config.Notifications.Email.Enabled),
			"notify_email":           config.Notifications.Email.To,
			"notify_host":            config.Notifications.Email.Host,
			"notify_port":            strconv.Itoa(config.Notifications.Email.Port),
			"notify_username":        config.Notifications.Email.Username,
			"notify_secure":          config.Notifications.Email.Security,
			"notify_tg_enabled":      strconv.FormatBool(config.Notifications.Telegram.Enabled),
			"notify_tg_chat_id":      config.Notifications.Telegram.ChatID,
			"notify_tg_proxy_type":   config.Notifications.Telegram.ProxyType,
			"notify_tg_proxy_ip":     config.Notifications.Telegram.ProxyIP,
			"notify_tg_proxy_port":   config.Notifications.Telegram.ProxyPort,
			"notify_tg_proxy_user":   config.Notifications.Telegram.ProxyUser,
			"notify_wh_enabled":      strconv.FormatBool(config.Notifications.Webhook.Enabled),
			"notify_wh_method":       config.Notifications.Webhook.Method,
			"notify_wh_request_type": config.Notifications.Webhook.Type,
			"notify_wh_provider":     config.Notifications.Webhook.Provider,
		}
		for key, value := range values {
			if err := putSettingTx(ctx, tx, key, value); err != nil {
				return err
			}
		}
		for key, value := range map[string]string{
			"notify_password":      config.Notifications.Email.Password,
			"notify_tg_token":      config.Notifications.Telegram.Token,
			"notify_tg_proxy_pass": config.Notifications.Telegram.ProxyPass,
			"notify_wh_headers":    config.Notifications.Webhook.Headers,
			"notify_wh_secret":     config.Notifications.Webhook.Secret,
		} {
			if err := s.saveSensitiveSetting(ctx, tx, key, value); err != nil {
				return err
			}
		}
		if err := s.saveSensitiveSetting(ctx, tx, "notify_wh_url", config.Notifications.Webhook.URL); err != nil {
			return err
		}
		if err := s.saveSensitiveSetting(ctx, tx, "notify_wh_body", config.Notifications.Webhook.Body); err != nil {
			return err
		}
		if err := s.saveSensitiveSetting(ctx, tx, "notify_tg_proxy_url", config.Notifications.Telegram.ProxyURL); err != nil {
			return err
		}

		if err := saveAccountsTx(ctx, tx, s, config.Accounts); err != nil {
			return err
		}
		return nil
	})
}

func (s *Store) saveSensitiveSetting(ctx context.Context, tx *sql.Tx, key, value string) error {
	if value == domain.ClearSecretSentinel {
		return putSettingTx(ctx, tx, key, "")
	}
	if value == "" {
		return nil
	}
	encrypted, err := s.EncryptAAD(value, key)
	if err != nil {
		return err
	}
	return putSettingTx(ctx, tx, key, encrypted)
}

func hashOrKeepPassword(password string) (string, error) {
	if security.IsCurrentPasswordHash(password) {
		return password, nil
	}
	return hashPassword(password)
}

// Kept in this file to make password migration explicit at the storage boundary.
func hashPassword(password string) (string, error) {
	return security.HashPassword(password)
}

func putSettingTx(ctx context.Context, tx *sql.Tx, key, value string) error {
	if key == "" || len([]rune(key)) > maxSettingKeyRunes || len(value) > maxSettingValueBytes {
		return errors.New("setting is too large")
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func validScheduleClock(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if len(value) != 5 {
		return false
	}
	parsed, err := time.Parse("15:04", value)
	return err == nil && parsed.Format("15:04") == value
}

func validAccountSiteType(value string) bool {
	switch value {
	case "china", "international":
		return true
	default:
		return false
	}
}

func validAccountToken(value string, max int, extra string) bool {
	if value == "" || len(value) > max {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if extra != "" && strings.ContainsRune(extra, rune(c)) {
			continue
		}
		return false
	}
	return true
}

func saveAccountsTx(ctx context.Context, tx *sql.Tx, s *Store, accounts []domain.Account) error {
	activeRows, err := tx.QueryContext(ctx, `SELECT id, access_key_id, region_id, instance_id, access_key_secret FROM accounts WHERE deleted_at=0`)
	if err != nil {
		return err
	}
	type existing struct {
		id, key, region, instance, secret string
	}
	byID := map[int64]existing{}
	byComposite := map[string]existing{}
	for activeRows.Next() {
		var id int64
		var row existing
		if err = activeRows.Scan(&id, &row.key, &row.region, &row.instance, &row.secret); err != nil {
			activeRows.Close()
			return err
		}
		row.id = fmt.Sprint(id)
		byID[id] = row
		byComposite[row.key+"|"+row.region+"|"+row.instance] = row
	}
	activeRows.Close()
	kept := make(map[int64]bool)
	for _, account := range accounts {
		account.AccessKeyID = strings.TrimSpace(account.AccessKeyID)
		account.RegionID = strings.TrimSpace(account.RegionID)
		account.InstanceID = strings.TrimSpace(account.InstanceID)
		if account.AccessKeyID == "" || account.RegionID == "" {
			return errors.New("account access_key_id and region_id are required")
		}
		if !validAccountToken(account.AccessKeyID, maxAccessKeyIDRunes, "-") {
			return errors.New("account access_key_id is invalid")
		}
		if !validAccountToken(account.RegionID, maxRegionIDRunes, "-") {
			return errors.New("account region_id is invalid")
		}
		if account.InstanceID != "" && !validAccountToken(account.InstanceID, maxInstanceIDRunes, "-_") {
			return errors.New("account instance_id is invalid")
		}
		account.StartTime = strings.TrimSpace(account.StartTime)
		account.StopTime = strings.TrimSpace(account.StopTime)
		if !validScheduleClock(account.StartTime) || !validScheduleClock(account.StopTime) {
			return errors.New("account schedule time is invalid")
		}
		account.Remark = strings.TrimSpace(account.Remark)
		if len([]rune(account.Remark)) > maxAccountRemarkRunes {
			return errors.New("account remark is too long")
		}
		if math.IsNaN(account.MaxTraffic) || math.IsInf(account.MaxTraffic, 0) || account.MaxTraffic <= 0 || account.MaxTraffic > maxAccountTrafficGB {
			return errors.New("account max traffic is invalid")
		}
		row, found := byID[account.ID]
		if !found {
			row, found = byComposite[account.AccessKeyID+"|"+account.RegionID+"|"+account.InstanceID]
		}
		secret := account.AccessKeySecret
		if secret != "" && len([]rune(secret)) > maxAccessKeySecretRunes {
			return errors.New("account access_key_secret is too long")
		}
		if secret == "" && found {
			secret, err = s.DecryptAAD(row.secret, security.AccountBoundAAD(row.key))
			if err != nil {
				return err
			}
		}
		if secret == "" {
			return fmt.Errorf("account %s is missing access key secret", account.AccessKeyID)
		}
		encryptedSecret, err := s.EncryptAAD(secret, security.AccountBoundAAD(account.AccessKeyID))
		if err != nil {
			return err
		}
		siteType := account.SiteType
		if siteType != "international" {
			siteType = "china"
		}
		if found {
			id, _ := strconv.ParseInt(row.id, 10, 64)
			_, err = tx.ExecContext(ctx, `UPDATE accounts SET access_key_id=?, access_key_secret=?, region_id=?, instance_id=?, max_traffic=?, schedule_enabled=?, start_time=?, stop_time=?, remark=?, site_type=?, deleted_at=0 WHERE id=?`,
				account.AccessKeyID, encryptedSecret, account.RegionID, account.InstanceID, account.MaxTraffic, boolInt(account.ScheduleEnabled), account.StartTime, account.StopTime, account.Remark, siteType, id)
			if err != nil {
				return err
			}
			kept[id] = true
		} else {
			result, err := tx.ExecContext(ctx, `INSERT INTO accounts(access_key_id,access_key_secret,region_id,instance_id,max_traffic,schedule_enabled,start_time,stop_time,remark,site_type,instance_status) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
				account.AccessKeyID, encryptedSecret, account.RegionID, account.InstanceID, account.MaxTraffic, boolInt(account.ScheduleEnabled), account.StartTime, account.StopTime, account.Remark, siteType, domain.StatusUnknown)
			if err != nil {
				return err
			}
			id, err := result.LastInsertId()
			if err != nil {
				return err
			}
			kept[id] = true
		}
	}
	if len(accounts) == 0 {
		_, err = tx.ExecContext(ctx, `UPDATE accounts SET deleted_at=unixepoch() WHERE deleted_at=0`)
		return err
	}
	for id := range byID {
		if !kept[id] {
			if _, err = tx.ExecContext(ctx, `UPDATE accounts SET deleted_at=unixepoch() WHERE id=?`, id); err != nil {
				return err
			}
		}
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (s *Store) ListAccounts(ctx context.Context) ([]domain.Account, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,access_key_id,access_key_secret,region_id,instance_id,max_traffic,schedule_enabled,start_time,stop_time,traffic_used,instance_status,updated_at,last_keep_alive_at,remark,site_type FROM accounts WHERE deleted_at=0 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []domain.Account
	for rows.Next() {
		var a domain.Account
		var secret string
		var schedule, updated, keepAlive int64
		if err = rows.Scan(&a.ID, &a.AccessKeyID, &secret, &a.RegionID, &a.InstanceID, &a.MaxTraffic, &schedule, &a.StartTime, &a.StopTime, &a.TrafficUsed, &a.InstanceStatus, &updated, &keepAlive, &a.Remark, &a.SiteType); err != nil {
			return nil, err
		}
		if len([]rune(a.Remark)) > maxAccountRemarkRunes {
			return nil, errors.New("account remark is too long")
		}
		if !validInstanceStatus(a.InstanceStatus) {
			return nil, errors.New("instance status is invalid")
		}
		if !validAccountSiteType(a.SiteType) {
			return nil, errors.New("site_type is invalid")
		}
		if !validAccountToken(a.AccessKeyID, maxAccessKeyIDRunes, "-") {
			return nil, errors.New("account access_key_id is invalid")
		}
		if !validAccountToken(a.RegionID, maxRegionIDRunes, "-") {
			return nil, errors.New("region_id is invalid")
		}
		if a.InstanceID != "" && !validAccountToken(a.InstanceID, maxInstanceIDRunes, "-_") {
			return nil, errors.New("instance_id is invalid")
		}
		if !validScheduleClock(a.StartTime) || !validScheduleClock(a.StopTime) {
			return nil, errors.New("schedule time is invalid")
		}
		if !validTrafficSample(a.TrafficUsed) {
			return nil, errors.New("traffic sample is invalid")
		}
		if math.IsNaN(a.MaxTraffic) || math.IsInf(a.MaxTraffic, 0) || a.MaxTraffic < 0 || a.MaxTraffic > maxAccountTrafficGB {
			return nil, errors.New("max traffic is invalid")
		}
		a.SecretConfigured = secret != ""
		a.ScheduleEnabled = schedule == 1
		if updated > 0 {
			a.UpdatedAt = time.Unix(updated, 0).UTC()
		}
		if keepAlive > 0 {
			a.LastKeepAliveAt = time.Unix(keepAlive, 0).UTC()
		}
		accounts = append(accounts, a)
	}
	return accounts, rows.Err()
}

func validAccountID(id int64) bool {
	return id >= 1
}

func (s *Store) GetAccount(ctx context.Context, id int64) (domain.Account, error) {
	if !validAccountID(id) {
		return domain.Account{}, sql.ErrNoRows
	}
	accounts, err := s.ListAccounts(ctx)
	if err != nil {
		return domain.Account{}, err
	}
	for _, account := range accounts {
		if account.ID == id {
			return account, nil
		}
	}
	return domain.Account{}, sql.ErrNoRows
}

func (s *Store) AccountSecrets(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT access_key_id, access_key_secret FROM accounts WHERE access_key_secret != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	secrets := make([]string, 0)
	for rows.Next() {
		var accessKeyID, encrypted string
		if err = rows.Scan(&accessKeyID, &encrypted); err != nil {
			return nil, err
		}
		plain, err := s.DecryptAAD(encrypted, security.AccountBoundAAD(accessKeyID))
		if err != nil || len(plain) < 4 {
			continue
		}
		secrets = append(secrets, plain)
	}
	return secrets, rows.Err()
}

func (s *Store) AccountSecret(ctx context.Context, id int64) (string, error) {
	if !validAccountID(id) {
		return "", sql.ErrNoRows
	}
	var encrypted, accessKeyID string
	err := s.db.QueryRowContext(ctx, `SELECT access_key_secret, access_key_id FROM accounts WHERE id=? AND deleted_at=0`, id).Scan(&encrypted, &accessKeyID)
	if err != nil {
		return "", err
	}
	return s.DecryptAAD(encrypted, security.AccountBoundAAD(accessKeyID))
}

func (s *Store) updateRuntime(ctx context.Context, id int64, traffic float64, status string, updatedAt time.Time) error {
	if !validAccountID(id) {
		return sql.ErrNoRows
	}
	if !validTrafficSample(traffic) {
		return errors.New("traffic sample is invalid")
	}
	if !validInstanceStatus(status) {
		return errors.New("instance status is invalid")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE accounts SET traffic_used=?,instance_status=?,updated_at=? WHERE id=? AND deleted_at=0`, traffic, status, updatedAt.Unix(), id)
	return err
}

func (s *Store) UpdateRuntime(ctx context.Context, id int64, traffic float64, status string, updatedAt time.Time) error {
	return s.updateRuntime(ctx, id, traffic, status, updatedAt)
}

func (s *Store) UpdateKeepAliveAt(ctx context.Context, id int64, at time.Time) error {
	if !validAccountID(id) {
		return sql.ErrNoRows
	}
	_, err := s.db.ExecContext(ctx, `UPDATE accounts SET last_keep_alive_at=? WHERE id=?`, at.Unix(), id)
	return err
}
