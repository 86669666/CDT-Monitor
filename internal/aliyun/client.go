package aliyun

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/domain"
)

type Provider interface {
	GetTraffic(ctx context.Context, account domain.Account, secret string) (float64, error)
	GetInstanceStatus(ctx context.Context, account domain.Account, secret string) (string, error)
	ControlInstance(ctx context.Context, account domain.Account, secret, action, shutdownMode string) error
	GetAccountBalance(ctx context.Context, account domain.Account, secret string) (BillingBalance, error)
	GetInstanceBill(ctx context.Context, account domain.Account, secret, cycle string) (BillingBill, error)
}

type BillingBalance struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

type BillingBill struct {
	TotalCost float64 `json:"total_cost"`
}

type Client struct {
	httpClient *http.Client
	trafficMu  sync.Mutex
	traffic    map[string]trafficCacheEntry
	balanceMu  sync.Mutex
	balance    map[string]balanceCacheEntry
}

type trafficCacheEntry struct {
	value     float64
	createdAt time.Time
}
type balanceCacheEntry struct {
	value     BillingBalance
	createdAt time.Time
}

var errAliyunRedirect = errors.New("aliyun redirects are not allowed")
var errAliyunForbiddenHost = errors.New("aliyun host is not allowed")

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 18 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
				DialContext:     aliyunDialContext,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errAliyunRedirect
			},
		},
		traffic: make(map[string]trafficCacheEntry),
		balance: make(map[string]balanceCacheEntry),
	}
}

func aliyunDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if addr.IP != nil {
				ips = append(ips, addr.IP)
			}
		}
	}
	if len(ips) == 0 {
		return nil, errAliyunForbiddenHost
	}
	for _, ip := range ips {
		if forbiddenAliyunIP(ip) {
			return nil, errAliyunForbiddenHost
		}
	}
	dialer := &net.Dialer{Timeout: 18 * time.Second}
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

func forbiddenAliyunIP(ip net.IP) bool {
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return ip.Equal(net.ParseIP("100.100.100.200")) || ip.Equal(net.ParseIP("fd00:ec2::254"))
}

func validECSRegion(region string) bool {
	region = strings.TrimSpace(region)
	if region == "" || len(region) > 32 {
		return false
	}
	for i := 0; i < len(region); i++ {
		c := region[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func (c *Client) GetTraffic(ctx context.Context, account domain.Account, secret string) (float64, error) {
	if strings.TrimSpace(account.RegionID) == "" {
		return 0, errors.New("region_id is required")
	}
	if !validECSRegion(account.RegionID) {
		return 0, errors.New("region_id is invalid")
	}
	key := account.AccessKeyID + ":" + trafficClass(account.RegionID)
	c.trafficMu.Lock()
	if cached, ok := c.traffic[key]; ok && time.Since(cached.createdAt) < 45*time.Second {
		c.trafficMu.Unlock()
		return cached.value, nil
	}
	c.trafficMu.Unlock()
	result, err := c.call(ctx, account.AccessKeyID, secret, "cn-hongkong", "cdt.aliyuncs.com", "2021-08-13", "ListCdtInternetTraffic", nil)
	if err != nil {
		return 0, err
	}
	value, err := trafficFromResponse(result, trafficClass(account.RegionID))
	if err != nil {
		return 0, err
	}
	c.trafficMu.Lock()
	c.traffic[key] = trafficCacheEntry{value: value, createdAt: time.Now()}
	c.trafficMu.Unlock()
	return value, nil
}

func trafficClass(region string) string {
	if strings.HasPrefix(region, "cn-") && region != "cn-hongkong" {
		return "china"
	}
	return "international"
}

func ecsTargetError(account domain.Account) error {
	if account.InstanceID == "" {
		return errors.New("instance_id is required")
	}
	if strings.TrimSpace(account.RegionID) == "" {
		return errors.New("region_id is required")
	}
	if !validECSRegion(account.RegionID) {
		return errors.New("region_id is invalid")
	}
	return nil
}

func (c *Client) GetInstanceStatus(ctx context.Context, account domain.Account, secret string) (string, error) {
	if err := ecsTargetError(account); err != nil {
		return domain.StatusUnknown, err
	}
	params := map[string]string{"RegionId": account.RegionID, "InstanceId": account.InstanceID}
	result, err := c.call(ctx, account.AccessKeyID, secret, account.RegionID, "ecs."+account.RegionID+".aliyuncs.com", "2014-05-26", "DescribeInstanceStatus", params)
	if err != nil {
		return domain.StatusUnknown, err
	}
	statuses := nestedSlice(result, "InstanceStatuses", "InstanceStatus")
	if len(statuses) == 0 {
		return domain.StatusUnknown, nil
	}
	first, ok := statuses[0].(map[string]any)
	if !ok {
		return domain.StatusUnknown, nil
	}
	status, _ := first["Status"].(string)
	return normalizeInstanceStatus(status), nil
}

func normalizeInstanceStatus(status string) string {
	if len(status) > 32 {
		return domain.StatusUnknown
	}
	switch status {
	case domain.StatusUnknown, domain.StatusRunning, domain.StatusStopped, domain.StatusStarting, domain.StatusStopping, "Pending":
		return status
	default:
		return domain.StatusUnknown
	}
}

func (c *Client) ControlInstance(ctx context.Context, account domain.Account, secret, action, shutdownMode string) error {
	if err := ecsTargetError(account); err != nil {
		return err
	}
	params := map[string]string{"RegionId": account.RegionID, "InstanceId": account.InstanceID}
	action = strings.ToLower(strings.TrimSpace(action))
	var apiAction string
	switch action {
	case "start":
		apiAction = "StartInstance"
	case "stop":
		apiAction = "StopInstance"
		if shutdownMode != "StopCharging" {
			shutdownMode = "KeepCharging"
		}
		params["StoppedMode"] = shutdownMode
	default:
		return errors.New("instance action is invalid")
	}
	_, err := c.call(ctx, account.AccessKeyID, secret, account.RegionID, "ecs."+account.RegionID+".aliyuncs.com", "2014-05-26", apiAction, params)
	return err
}

func (c *Client) GetAccountBalance(ctx context.Context, account domain.Account, secret string) (BillingBalance, error) {
	key := account.AccessKeyID + ":" + billingSite(account.SiteType)
	c.balanceMu.Lock()
	if cached, ok := c.balance[key]; ok && time.Since(cached.createdAt) < 6*time.Hour {
		c.balanceMu.Unlock()
		return cached.value, nil
	}
	c.balanceMu.Unlock()
	bss := bssEndpoint(account.SiteType)
	result, err := c.call(ctx, account.AccessKeyID, secret, bss.region, bss.host, "2017-12-14", "QueryAccountBalance", nil)
	if err != nil {
		return BillingBalance{}, err
	}
	data, _ := result["Data"].(map[string]any)
	value := BillingBalance{Amount: number(data["AvailableAmount"]), Currency: stringValue(data["Currency"])}
	if value.Currency == "" {
		value.Currency = "CNY"
	}
	c.balanceMu.Lock()
	c.balance[key] = balanceCacheEntry{value: value, createdAt: time.Now()}
	c.balanceMu.Unlock()
	return value, nil
}

func (c *Client) GetInstanceBill(ctx context.Context, account domain.Account, secret, cycle string) (BillingBill, error) {
	if account.InstanceID == "" {
		return BillingBill{}, errors.New("instance_id is required")
	}
	if err := validBillingCycle(cycle); err != nil {
		return BillingBill{}, err
	}
	bss := bssEndpoint(account.SiteType)
	params := map[string]string{"BillingCycle": cycle, "InstanceID": account.InstanceID, "Granularity": "MONTHLY"}
	result, err := c.call(ctx, account.AccessKeyID, secret, bss.region, bss.host, "2017-12-14", "DescribeInstanceBill", params)
	if err != nil {
		return BillingBill{}, err
	}
	data, _ := result["Data"].(map[string]any)
	items := asSlice(data["Items"])
	if nested := nestedSlice(data, "Items", "Item"); len(nested) > 0 {
		items = nested
	}
	var total float64
	for _, item := range items {
		if obj, ok := item.(map[string]any); ok {
			total += number(obj["PretaxAmount"])
		}
	}
	return BillingBill{TotalCost: math.Round(total*100) / 100}, nil
}

type bssConfig struct{ region, host string }

func bssEndpoint(siteType string) bssConfig {
	if billingSite(siteType) == "international" {
		return bssConfig{region: "ap-southeast-1", host: "business.ap-southeast-1.aliyuncs.com"}
	}
	return bssConfig{region: "cn-hangzhou", host: "business.aliyuncs.com"}
}

func billingSite(siteType string) string {
	if siteType == "international" {
		return "international"
	}
	return "china"
}

func validBillingCycle(cycle string) error {
	cycle = strings.TrimSpace(cycle)
	parsed, err := time.Parse("2006-01", cycle)
	if err != nil || parsed.Format("2006-01") != cycle {
		return errors.New("billing cycle is required")
	}
	return nil
}

func allowedAliyunAction(action string) bool {
	switch action {
	case "ListCdtInternetTraffic", "DescribeInstanceStatus", "StartInstance", "StopInstance", "QueryAccountBalance", "DescribeInstanceBill":
		return true
	default:
		return false
	}
}

func allowedAliyunVersion(version string) bool {
	switch version {
	case "2014-05-26", "2017-12-14", "2021-08-13":
		return true
	default:
		return false
	}
}

func allowedAliyunHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || strings.ContainsAny(host, "/:@") {
		return false
	}
	switch host {
	case "cdt.aliyuncs.com", "business.aliyuncs.com", "business.ap-southeast-1.aliyuncs.com":
		return true
	}
	const prefix, suffix = "ecs.", ".aliyuncs.com"
	if !strings.HasPrefix(host, prefix) || !strings.HasSuffix(host, suffix) {
		return false
	}
	return validECSRegion(strings.TrimSuffix(strings.TrimPrefix(host, prefix), suffix))
}

func (c *Client) call(ctx context.Context, accessKeyID, secret, region, host, version, action string, extras map[string]string) (map[string]any, error) {
	if strings.TrimSpace(accessKeyID) == "" || secret == "" {
		return nil, errors.New("access key is required")
	}
	if !allowedAliyunAction(action) {
		return nil, errors.New("aliyun action is invalid")
	}
	if !allowedAliyunHost(host) {
		return nil, errors.New("aliyun host is invalid")
	}
	if !allowedAliyunVersion(version) {
		return nil, errors.New("aliyun version is invalid")
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		result, retry, err := c.callOnce(ctx, accessKeyID, secret, region, host, version, action, extras)
		if err == nil {
			return result, nil
		}
		last = err
		if !retry || attempt == 2 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, redactErr(ctx.Err(), accessKeyID, secret)
		case <-time.After(time.Duration(1<<attempt)*300*time.Millisecond + time.Duration(attempt*100)*time.Millisecond):
		}
	}
	return nil, redactErr(last, accessKeyID, secret)
}

func redactErr(err error, accessKeyID, secret string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if secret != "" {
		msg = strings.ReplaceAll(msg, secret, "[redacted]")
	}
	if accessKeyID != "" {
		masked := accessKeyID + "***"
		if len(accessKeyID) > 7 {
			masked = accessKeyID[:7] + "***"
		}
		msg = strings.ReplaceAll(msg, accessKeyID, masked)
	}
	if msg == err.Error() {
		return err
	}
	return errors.New(msg)
}

func (c *Client) callOnce(ctx context.Context, accessKeyID, secret, region, host, version, action string, extras map[string]string) (map[string]any, bool, error) {
	params := map[string]string{
		"AccessKeyId":      accessKeyID,
		"Action":           action,
		"Format":           "JSON",
		"RegionId":         region,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   randomNonce(),
		"SignatureVersion": "1.0",
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"Version":          version,
	}
	for key, value := range extras {
		params[key] = value
	}
	params["Signature"] = sign(params, secret)
	form := url.Values{}
	for key, value := range params {
		form.Set(key, value)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, true, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, true, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode >= 500, err
	}
	var result map[string]any
	if err = json.Unmarshal(body, &result); err != nil {
		return nil, resp.StatusCode >= 500, fmt.Errorf("aliyun %s invalid response: %w", action, err)
	}
	if resp.StatusCode >= 400 {
		return nil, resp.StatusCode >= 500 || resp.StatusCode == 429, fmt.Errorf("aliyun %s http %d: %s", action, resp.StatusCode, compactMessage(result, body))
	}
	if code := stringValue(result["Code"]); code != "" && !isSuccessCode(code) {
		return nil, strings.Contains(strings.ToLower(code), "throttl"), fmt.Errorf("aliyun %s %s: %s", action, code, stringValue(result["Message"]))
	}
	return result, false, nil
}

func isSuccessCode(code string) bool {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "ok", "200", "success":
		return true
	default:
		return false
	}
}

func compactMessage(result map[string]any, raw []byte) string {
	if message := stringValue(result["Message"]); message != "" {
		return message
	}
	text := strings.TrimSpace(string(raw))
	if len(text) > 240 {
		return text[:240] + "..."
	}
	return text
}

func sign(values map[string]string, secret string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if key != "Signature" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for index, key := range keys {
		if index > 0 {
			canonical.WriteByte('&')
		}
		canonical.WriteString(percentEncode(key))
		canonical.WriteByte('=')
		canonical.WriteString(percentEncode(values[key]))
	}
	stringToSign := "POST&%2F&" + percentEncode(canonical.String())
	hash := hmac.New(sha1.New, []byte(secret+"&"))
	_, _ = hash.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func percentEncode(value string) string {
	encoded := url.QueryEscape(value)
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	encoded = strings.ReplaceAll(encoded, "*", "%2A")
	return strings.ReplaceAll(encoded, "%7E", "~")
}

func randomNonce() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return hex.EncodeToString(raw)
}

func trafficFromResponse(result map[string]any, class string) (float64, error) {
	items := asSlice(result["TrafficDetails"])
	if len(items) == 0 {
		if data, ok := result["Data"].(map[string]any); ok {
			items = asSlice(data["TrafficDetails"])
		}
	}
	if len(items) == 0 {
		return 0, errors.New("CDT response has no TrafficDetails")
	}
	var total float64
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		region := stringValue(obj["BusinessRegionId"])
		if trafficClass(region) == class {
			total += number(obj["Traffic"])
		}
	}
	return total / (1024 * 1024 * 1024), nil
}

func nestedSlice(value map[string]any, parents ...string) []any {
	var current any = value
	for _, key := range parents {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = obj[key]
	}
	return asSlice(current)
}

func asSlice(value any) []any {
	if values, ok := value.([]any); ok {
		return values
	}
	if obj, ok := value.(map[string]any); ok {
		if values, ok := obj["Item"].([]any); ok {
			return values
		}
		if item, ok := obj["Item"].(map[string]any); ok {
			return []any{item}
		}
		return []any{obj}
	}
	return nil
}

func number(value any) float64 {
	switch number := value.(type) {
	case float64:
		return number
	case json.Number:
		result, _ := number.Float64()
		return result
	case string:
		result, _ := strconv.ParseFloat(number, 64)
		return result
	default:
		return 0
	}
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}
