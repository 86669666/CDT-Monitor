package aliyun

import (
	"context"
	"errors"
	"strings"
	"unicode"

	"github.com/wang4386/CDT-Monitor/internal/domain"
)

const DiscoveryPageSize = 50

type DiscoveredInstance struct {
	InstanceID   string `json:"instance_id"`
	InstanceName string `json:"instance_name"`
	RegionID     string `json:"region_id"`
	Status       string `json:"status"`
	ChargeType   string `json:"charge_type"`
}
type DiscoveryPage struct {
	Instances []DiscoveredInstance `json:"instances"`
	NextToken string               `json:"next_token"`
}
type InstanceDiscoveryProvider interface {
	DiscoverInstances(context.Context, domain.Account, string, string) (DiscoveryPage, error)
}

func validDiscoveryToken(token string) bool {
	if len(token) > 2048 {
		return false
	}
	for _, c := range token {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

func ValidDiscoveryInput(key, secret, region, token string) bool {
	if len(key) < 1 || len(key) > 64 || len([]rune(secret)) < 1 || len([]rune(secret)) > 128 || strings.TrimSpace(secret) != secret || !validECSRegion(region) || !validDiscoveryToken(token) {
		return false
	}
	for _, c := range key {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	for _, c := range secret {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func (c *Client) DiscoverInstances(ctx context.Context, account domain.Account, secret, token string) (DiscoveryPage, error) {
	page := DiscoveryPage{Instances: []DiscoveredInstance{}}
	if !ValidDiscoveryInput(account.AccessKeyID, secret, account.RegionID, token) {
		return page, errors.New("invalid discovery input")
	}
	extras := map[string]string{"RegionId": account.RegionID, "MaxResults": "50"}
	if token != "" {
		extras["NextToken"] = token
	}
	result, err := c.call(ctx, account.AccessKeyID, secret, account.RegionID, "ecs."+account.RegionID+".aliyuncs.com", "2014-05-26", "DescribeInstances", extras)
	if err != nil {
		return page, err
	}
	envelope, ok := result["Instances"].(map[string]any)
	if !ok {
		return page, errors.New("invalid discovery response")
	}
	rows, ok := envelope["Instance"].([]any)
	if !ok || len(rows) > DiscoveryPageSize {
		return page, errors.New("invalid discovery response")
	}
	if raw, exists := result["NextToken"]; exists && raw != nil {
		page.NextToken, ok = raw.(string)
		if !ok || !validDiscoveryToken(page.NextToken) || (page.NextToken != "" && page.NextToken == token) {
			return DiscoveryPage{}, errors.New("invalid discovery cursor")
		}
	}
	seen := map[string]bool{}
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return DiscoveryPage{}, errors.New("invalid discovery instance")
		}
		id, _ := row["InstanceId"].(string)
		region, _ := row["RegionId"].(string)
		if !validAliyunInstanceID(id) || region != account.RegionID || seen[id] {
			return DiscoveryPage{}, errors.New("invalid discovery instance identity")
		}
		seen[id] = true
		name, _ := row["InstanceName"].(string)
		name = strings.TrimSpace(strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, name))
		if len([]rune(name)) > 128 {
			name = string([]rune(name)[:128])
		}
		charge, _ := row["InstanceChargeType"].(string)
		spot, _ := row["SpotStrategy"].(string)
		status, _ := row["Status"].(string)
		page.Instances = append(page.Instances, DiscoveredInstance{InstanceID: id, InstanceName: name, RegionID: region, Status: normalizeInstanceStatus(status), ChargeType: classifyInstanceChargeType(charge, spot)})
	}
	return page, nil
}
