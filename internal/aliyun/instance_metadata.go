package aliyun

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/wang4386/CDT-Monitor/internal/domain"
)

// Optional capability so status/traffic providers do not require billing access.
type InstanceMetadataProvider interface {
	GetInstanceChargeType(context.Context, domain.Account, string) (string, error)
}

type InstanceDetails struct {
	ChargeType string
	PublicIPv4 string
	IPv6       string
}

// InstanceDetailsProvider extends the existing optional metadata capability.
// It collects addresses from the same DescribeInstances response.
type InstanceDetailsProvider interface {
	GetInstanceMetadata(context.Context, domain.Account, string) (InstanceDetails, error)
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
	details, err := c.GetInstanceMetadata(ctx, account, secret)
	if err != nil {
		return "unknown", err
	}
	return details.ChargeType, nil
}

func (c *Client) GetInstanceMetadata(ctx context.Context, account domain.Account, secret string) (InstanceDetails, error) {
	if err := ecsTargetError(account); err != nil {
		return InstanceDetails{}, err
	}
	ids, _ := json.Marshal([]string{account.InstanceID})
	result, err := c.call(ctx, account.AccessKeyID, secret, account.RegionID, "ecs."+account.RegionID+".aliyuncs.com", "2014-05-26", "DescribeInstances", map[string]string{"RegionId": account.RegionID, "InstanceIds": string(ids)})
	if err != nil {
		return InstanceDetails{}, err
	}
	for _, row := range nestedSlice(result, "Instances", "Instance") {
		instance, ok := row.(map[string]any)
		if !ok || instance["InstanceId"] != account.InstanceID {
			continue
		}
		charge, _ := instance["InstanceChargeType"].(string)
		spot, _ := instance["SpotStrategy"].(string)
		ipv4 := firstInstanceAddress(instance["EipAddress"], false)
		if ipv4 == "" {
			ipv4 = firstInstanceAddress(instance["PublicIpAddress"], false)
		}
		ipv6 := firstInstanceAddress(instance["Ipv6Address"], true)
		if ipv6 == "" {
			ipv6 = firstInstanceAddress(instance["Ipv6Addresses"], true)
		}
		if ipv6 == "" {
			for _, path := range [][]string{{"NetworkInterface"}, {"NetworkInterfaces", "NetworkInterface"}} {
				for _, row := range nestedSlice(instance, path...) {
					if nic, ok := row.(map[string]any); ok {
						ipv6 = firstInstanceAddress(nestedSlice(nic, "Ipv6Sets", "Ipv6Set"), true)
						if ipv6 != "" {
							break
						}
					}
				}
				if ipv6 != "" {
					break
				}
			}
		}
		return InstanceDetails{ChargeType: classifyInstanceChargeType(charge, spot), PublicIPv4: ipv4, IPv6: ipv6}, nil
	}
	return InstanceDetails{}, errors.New("instance metadata not found")
}

func firstInstanceAddress(value any, ipv6 bool) string {
	switch typed := value.(type) {
	case string:
		address, err := netip.ParseAddr(typed)
		if err == nil && address.Zone() == "" && ((ipv6 && address.Is6() && !address.Is4In6()) || (!ipv6 && address.Is4())) {
			return address.String()
		}
	case []any:
		for _, item := range typed {
			if address := firstInstanceAddress(item, ipv6); address != "" {
				return address
			}
		}
	case map[string]any:
		for _, key := range []string{"IpAddress", "Ipv6Address", "Address"} {
			if address := firstInstanceAddress(typed[key], ipv6); address != "" {
				return address
			}
		}
	}
	return ""
}
