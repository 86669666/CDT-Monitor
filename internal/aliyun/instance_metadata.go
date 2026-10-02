package aliyun

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/wang4386/CDT-Monitor/internal/domain"
)

// Optional capability so status/traffic providers do not require billing access.
type InstanceMetadataProvider interface {
	GetInstanceChargeType(context.Context, domain.Account, string) (string, error)
}

func classifyInstanceChargeType(charge, spot string) string {
	switch {
	case charge == "PrePaid" && (spot == "NoSpot" || spot == ""):
		return "subscription"
	case charge == "PostPaid" && (spot == "SpotWithPriceLimit" || spot == "SpotAsPriceGo"):
		return "spot"
	case charge == "PostPaid" && spot == "NoSpot":
		return "pay_as_you_go"
	default:
		return "unknown"
	}
}

func (c *Client) GetInstanceChargeType(ctx context.Context, account domain.Account, secret string) (string, error) {
	if err := ecsTargetError(account); err != nil {
		return "unknown", err
	}
	ids, _ := json.Marshal([]string{account.InstanceID})
	result, err := c.call(ctx, account.AccessKeyID, secret, account.RegionID, "ecs."+account.RegionID+".aliyuncs.com", "2014-05-26", "DescribeInstances", map[string]string{"RegionId": account.RegionID, "InstanceIds": string(ids)})
	if err != nil {
		return "unknown", err
	}
	for _, row := range nestedSlice(result, "Instances", "Instance") {
		instance, ok := row.(map[string]any)
		if !ok || instance["InstanceId"] != account.InstanceID {
			continue
		}
		charge, _ := instance["InstanceChargeType"].(string)
		spot, _ := instance["SpotStrategy"].(string)
		return classifyInstanceChargeType(charge, spot), nil
	}
	return "unknown", errors.New("instance metadata not found")
}
