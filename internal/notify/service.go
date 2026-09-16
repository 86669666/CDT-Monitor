package notify

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/wang4386/CDT-Monitor/internal/domain"
)

type Service struct {
	httpClient *http.Client
}

var errNotifyRedirect = errors.New("notification redirects are not allowed")

func New() *Service {
	return &Service{httpClient: notifyHTTPClient(12*time.Second, nil)}
}

func notifyHTTPClient(timeout time.Duration, transport http.RoundTripper) *http.Client {
	if transport == nil {
		transport = tls12Transport(nil)
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errNotifyRedirect
		},
	}
}

func tls12Transport(base *http.Transport) *http.Transport {
	if base == nil {
		base = &http.Transport{}
	}
	if base.TLSClientConfig == nil {
		base.TLSClientConfig = &tls.Config{}
	}
	cloned := base.TLSClientConfig.Clone()
	cloned.MinVersion = tls.VersionTLS12
	base.TLSClientConfig = cloned
	if base.DialContext == nil {
		base.DialContext = notifyDialContext
	}
	return base
}

func EnabledChannels(config domain.Config) []string {
	channels := make([]string, 0, 3)
	if config.Notifications.Email.Enabled && config.Notifications.Email.To != "" {
		channels = append(channels, "email")
	}
	if config.Notifications.Telegram.Enabled && config.Notifications.Telegram.Token != "" && config.Notifications.Telegram.ChatID != "" {
		channels = append(channels, "telegram")
	}
	if config.Notifications.Webhook.Enabled && config.Notifications.Webhook.URL != "" {
		channels = append(channels, "webhook")
	}
	return channels
}

func (s *Service) Send(ctx context.Context, channel string, event domain.NotificationEvent, config domain.Config) error {
	var err error
	switch channel {
	case "email":
		err = sendEmail(ctx, config.Notifications.Email, event)
	case "telegram":
		err = s.sendTelegram(ctx, config.Notifications.Telegram, event)
	case "webhook":
		err = s.sendWebhook(ctx, config.Notifications.Webhook, event)
	default:
		return fmt.Errorf("unsupported notification channel %q", channel)
	}
	return sanitizeNotificationError(err, config)
}

func RedactSecrets(message string, config domain.Config, extraSecrets ...string) string {
	if message == "" {
		return ""
	}
	err := sanitizeNotificationError(errors.New(message), config, extraSecrets...)
	if err == nil {
		return ""
	}
	return err.Error()
}

func sanitizeNotificationError(err error, config domain.Config, extraSecrets ...string) error {
	if err == nil {
		return nil
	}
	secrets := notificationSecrets(config, extraSecrets...)
	if len(secrets) == 0 {
		return err
	}
	msg := err.Error()
	redacted := msg
	for _, secret := range secrets {
		redacted = strings.ReplaceAll(redacted, secret, "[redacted]")
	}
	if redacted == msg {
		return err
	}
	return errors.New(redacted)
}

func notificationSecrets(config domain.Config, extraSecrets ...string) []string {
	n := config.Notifications
	candidates := []string{
		n.Webhook.URL,
		n.Webhook.Headers,
		n.Webhook.Secret,
		n.Webhook.Body,
		n.Telegram.ProxyURL,
		n.Telegram.Token,
		n.Telegram.ChatID,
		n.Telegram.ProxyUser,
		n.Telegram.ProxyPass,
		n.Email.Password,
		n.Email.Username,
		n.Email.To,
	}
	candidates = append(candidates, extraSecrets...)
	for _, account := range config.Accounts {
		candidates = append(candidates, account.AccessKeySecret)
	}
	secrets := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if len(candidate) < 4 {
			continue
		}
		secrets = append(secrets, candidate)
	}
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	return secrets
}

var (
	errUnsupportedNotifyScheme = errors.New("notification URL must use http or https")
	errForbiddenNotifyHost     = errors.New("notification URL host is not allowed")
	errInvalidNotifyHeader     = errors.New("notification header fields must not contain line breaks")
)

func ValidateCallbackURL(raw string) error {
	return validateNotifyURL(raw, []string{"http", "https"})
}

func ValidateProxyURL(raw string) error {
	return validateNotifyURL(raw, []string{"http", "https", "socks5", "socks4"})
}

func validateNotifyURL(raw string, schemes []string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == domain.ClearSecretSentinel {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid notification URL: %w", err)
	}
	if !contains(schemes, parsed.Scheme) {
		return errUnsupportedNotifyScheme
	}
	host := parsed.Hostname()
	if host == "" {
		return errors.New("notification URL host is required")
	}
	if strings.Contains(host, "#") {
		return nil
	}
	if forbiddenNotifyHost(host) {
		return errForbiddenNotifyHost
	}
	return nil
}

func ValidateDialHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	if forbiddenNotifyHost(host) {
		return errForbiddenNotifyHost
	}
	return nil
}

func containsHeaderBreak(value string) bool {
	for _, r := range value {
		if r == '\r' || r == '\n' || r == 0 {
			return true
		}
	}
	return false
}

func ValidateSMTPIdentity(username, to string) error {
	if containsHeaderBreak(username) || containsHeaderBreak(to) {
		return errInvalidNotifyHeader
	}
	return nil
}

func ValidateWebhookHeaders(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == domain.ClearSecretSentinel {
		return nil
	}
	var headers map[string]string
	if err := json.Unmarshal([]byte(raw), &headers); err != nil {
		if containsHeaderBreak(raw) {
			return errInvalidNotifyHeader
		}
		return nil
	}
	for key, value := range headers {
		if containsHeaderBreak(key) || containsHeaderBreak(value) {
			return errInvalidNotifyHeader
		}
	}
	return nil
}

var lookupNotifyIPs = func(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP != nil {
			ips = append(ips, addr.IP)
		}
	}
	return ips, nil
}

func validateNotifyDestination(ctx context.Context, raw string) error {
	if err := ValidateCallbackURL(raw); err != nil {
		return err
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return err
	}
	return resolveForbiddenHost(ctx, parsed.Hostname())
}

func resolveForbiddenHost(ctx context.Context, host string) error {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || strings.Contains(host, "#") || net.ParseIP(host) != nil {
		return nil
	}
	if forbiddenNotifyHost(host) {
		return errForbiddenNotifyHost
	}
	ips, err := lookupNotifyIPs(ctx, host)
	if err != nil {
		return fmt.Errorf("notification URL host lookup failed: %w", err)
	}
	for _, ip := range ips {
		if forbiddenNotifyIP(ip) {
			return errForbiddenNotifyHost
		}
	}
	return nil
}

func notifyDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if err = ValidateDialHost(host); err != nil {
		return nil, err
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		ips, err = lookupNotifyIPs(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("notification URL host lookup failed: %w", err)
		}
	}
	if len(ips) == 0 {
		return nil, errForbiddenNotifyHost
	}
	for _, ip := range ips {
		if forbiddenNotifyIP(ip) {
			return nil, errForbiddenNotifyHost
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var lastErr error
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func forbiddenNotifyHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	switch host {
	case "metadata.google.internal", "metadata.google.com", "metadata.aliyuncs.com":
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return forbiddenNotifyIP(ip)
}

func forbiddenNotifyIP(ip net.IP) bool {
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip.Equal(net.ParseIP("100.100.100.200")) || ip.Equal(net.ParseIP("fd00:ec2::254")) {
		return true
	}
	return false
}

func sendEmail(ctx context.Context, config domain.EmailConfig, event domain.NotificationEvent) error {
	if config.Host == "" || config.Port == 0 || config.Username == "" || config.To == "" {
		return errors.New("SMTP host, port, username and recipient are required")
	}
	if err := ValidateSMTPIdentity(config.Username, config.To); err != nil {
		return err
	}
	if err := ValidateDialHost(config.Host); err != nil {
		return err
	}
	if err := resolveForbiddenHost(ctx, config.Host); err != nil {
		return err
	}
	hostPort := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	useImplicitTLS := strings.EqualFold(config.Security, "ssl") || config.Port == 465
	conn, err := notifyDialContext(ctx, "tcp", hostPort)
	if err != nil {
		return err
	}
	if useImplicitTLS {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: config.Host, MinVersion: tls.VersionTLS12})
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return err
		}
		conn = tlsConn
	}
	client, err := smtp.NewClient(conn, config.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer client.Close()
	if !useImplicitTLS && (strings.EqualFold(config.Security, "tls") || strings.EqualFold(config.Security, "starttls")) {
		if err = client.StartTLS(&tls.Config{ServerName: config.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if config.Password != "" {
		if err := client.Auth(smtp.PlainAuth("", config.Username, config.Password, config.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(config.Username); err != nil {
		return err
	}
	if err := client.Rcpt(config.To); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	subject := mime.QEncoding.Encode("UTF-8", "CDT Monitor · "+event.Title)
	message := "From: CDT Monitor <" + config.Username + ">\r\n" +
		"To: " + config.To + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n" + renderEmail(event)
	if _, err = io.WriteString(writer, message); err != nil {
		writer.Close()
		return err
	}
	if err = writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func renderEmail(event domain.NotificationEvent) string {
	var rows strings.Builder
	for key, value := range event.Fields {
		rows.WriteString("<tr><td style=\"padding:12px 0;color:#8e8e93;border-bottom:1px solid #eee\">")
		rows.WriteString(html.EscapeString(key))
		rows.WriteString("</td><td style=\"padding:12px 0;text-align:right;font-weight:700;border-bottom:1px solid #eee\">")
		rows.WriteString(html.EscapeString(value))
		rows.WriteString("</td></tr>")
	}
	return `<!doctype html><html><body style="margin:0;background:#f2f2f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#1c1c1e"><table width="100%"><tr><td align="center" style="padding:40px 20px"><table width="100%" style="max-width:560px;background:rgba(255,255,255,.92);border:1px solid #fff;border-radius:28px;box-shadow:0 24px 48px -12px rgba(0,0,0,.08)"><tr><td style="padding:36px"><div style="font-size:11px;font-weight:800;letter-spacing:.16em;color:#6e6e73">CDT MONITOR</div><h1 style="font-size:26px;margin:10px 0">` + html.EscapeString(event.Title) + `</h1><p style="color:#6e6e73">` + html.EscapeString(event.Summary) + `</p><table width="100%" style="margin-top:24px;border-top:1px solid #eee">` + rows.String() + `</table></td></tr></table></td></tr></table></body></html>`
}

func (s *Service) sendTelegram(ctx context.Context, config domain.TelegramConfig, event domain.NotificationEvent) error {
	baseURL := "https://api.telegram.org"
	if config.ProxyType == "custom" && config.ProxyURL != "" {
		baseURL = strings.TrimRight(config.ProxyURL, "/")
	}
	endpoint := baseURL + "/bot" + config.Token + "/sendMessage"
	if err := validateNotifyDestination(ctx, endpoint); err != nil {
		return err
	}
	if err := ValidateDialHost(config.ProxyIP); err != nil {
		return err
	}
	if err := resolveForbiddenHost(ctx, config.ProxyIP); err != nil {
		return err
	}
	form := url.Values{"chat_id": {config.ChatID}, "text": {eventText(event)}}
	client := s.httpClient
	if config.ProxyType == "socks5" && config.ProxyIP != "" && config.ProxyPort != "" {
		var auth *proxy.Auth
		if config.ProxyUser != "" || config.ProxyPass != "" {
			auth = &proxy.Auth{User: config.ProxyUser, Password: config.ProxyPass}
		}
		dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort(config.ProxyIP, config.ProxyPort), auth, proxy.Direct)
		if err != nil {
			return err
		}
		client = notifyHTTPClient(12*time.Second, tls12Transport(&http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.Dial(network, address)
		}}))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (s *Service) sendWebhook(ctx context.Context, config domain.WebhookConfig, event domain.NotificationEvent) error {
	replacements := replacements(event)
	endpoint := replaceTemplate(config.URL, replacements, true)
	if strings.TrimSpace(endpoint) == "" {
		return errors.New("webhook URL is required")
	}
	if strings.EqualFold(config.Provider, "dingtalk") && config.Secret != "" {
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		mac := hmac.New(sha256.New, []byte(config.Secret))
		_, _ = mac.Write([]byte(timestamp + "\n" + config.Secret))
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return err
		}
		query := parsed.Query()
		query.Set("timestamp", timestamp)
		query.Set("sign", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
		parsed.RawQuery = query.Encode()
		endpoint = parsed.String()
	}
	method := strings.ToUpper(config.Method)
	if method != http.MethodPost {
		method = http.MethodGet
	}
	var body io.Reader
	if method == http.MethodGet {
		if !strings.Contains(config.URL, "#") {
			parsed, err := url.Parse(endpoint)
			if err != nil {
				return err
			}
			query := parsed.Query()
			query.Set("title", event.Title)
			query.Set("message", event.Summary)
			parsed.RawQuery = query.Encode()
			endpoint = parsed.String()
		}
	} else {
		payload := config.Body
		if payload == "" {
			defaultPayload := map[string]any{"title": event.Title, "summary": event.Summary, "type": event.Type, "fields": event.Fields, "created_at": event.CreatedAt}
			if strings.EqualFold(config.Type, "FORM") {
				form := url.Values{"title": {event.Title}, "summary": {event.Summary}, "type": {event.Type}}
				payload = form.Encode()
			} else {
				encoded, _ := json.Marshal(defaultPayload)
				payload = string(encoded)
			}
		} else {
			payload = replaceTemplate(payload, replacements, strings.EqualFold(config.Type, "FORM"))
		}
		body = strings.NewReader(payload)
	}
	if err := validateNotifyDestination(ctx, endpoint); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	if method == http.MethodPost {
		if strings.EqualFold(config.Type, "FORM") {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if config.Headers != "" {
		var headers map[string]string
		if err = json.Unmarshal([]byte(config.Headers), &headers); err != nil {
			return fmt.Errorf("invalid webhook headers: %w", err)
		}
		if err = ValidateWebhookHeaders(config.Headers); err != nil {
			return err
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook HTTP %d: %s", resp.StatusCode, string(responseBody))
	}
	return nil
}

func eventText(event domain.NotificationEvent) string {
	var builder strings.Builder
	builder.WriteString("[CDT Monitor] ")
	builder.WriteString(event.Title)
	builder.WriteByte('\n')
	builder.WriteString(event.Summary)
	for key, value := range event.Fields {
		builder.WriteByte('\n')
		builder.WriteString(key)
		builder.WriteString(": ")
		builder.WriteString(value)
	}
	return builder.String()
}

func replacements(event domain.NotificationEvent) map[string]string {
	traffic := event.Fields["当前流量"]
	traffic = strings.TrimSpace(strings.TrimSuffix(traffic, "GB"))
	threshold := event.Fields["设定阈值"]
	threshold = strings.TrimSpace(strings.TrimSuffix(threshold, "%"))
	instance := event.Fields["实例"]
	status := event.Fields["实例状态"]
	createdAt := event.CreatedAt.UTC().Format(time.RFC3339)
	return map[string]string{
		"#TITLE#":             event.Title,
		"#MSG#":               event.Summary,
		"#ACCOUNT#":           strconv.FormatInt(event.AccountID, 10),
		"#ACCOUNT_ID#":        strconv.FormatInt(event.AccountID, 10),
		"#TRAFFIC#":           traffic,
		"#TRAFFIC_GB#":        traffic,
		"#MAX_TRAFFIC#":       threshold,
		"#THRESHOLD_PERCENT#": threshold,
		"#INSTANCE#":          instance,
		"#STATUS#":            status,
		"#TYPE#":              event.Type,
		"#CREATED_AT#":        createdAt,
		"#TIME#":              createdAt,
	}
}

func replaceTemplate(input string, replacements map[string]string, urlEncode bool) string {
	for key, value := range replacements {
		if urlEncode {
			value = url.QueryEscape(value)
		} else {
			encoded, _ := json.Marshal(value)
			value = strings.Trim(string(encoded), "\"")
		}
		input = strings.ReplaceAll(input, key, value)
	}
	return input
}

// ReadDotResponse is kept private to avoid accepting unbounded SMTP responses.
func readDotResponse(reader *bufio.Reader) ([]byte, error) {
	var buffer bytes.Buffer
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		if string(line) == ".\r\n" {
			return buffer.Bytes(), nil
		}
		buffer.Write(line)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
