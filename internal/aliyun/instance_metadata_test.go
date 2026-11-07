package aliyun

import (
	"context"
	"fmt"
	"github.com/wang4386/CDT-Monitor/internal/domain"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestInstancePurchaseTypes(t *testing.T) {
	for _, tc := range []struct{ charge, spot, want string }{
		{"PrePaid", "NoSpot", "subscription"}, {"PrePaid", "", "subscription"},
		{"PostPaid", "NoSpot", "pay_as_you_go"}, {"PostPaid", "SpotWithPriceLimit", "spot"}, {"PostPaid", "SpotAsPriceGo", "spot"},
		{"PostPaid", "", "unknown"}, {"", "NoSpot", "unknown"}, {"PrePaid", "SpotAsPriceGo", "unknown"}, {"new", "new", "unknown"},
	} {
		if got := classifyInstanceChargeType(tc.charge, tc.spot); got != tc.want {
			t.Fatalf("%+v got %s", tc, got)
		}
	}
}

func TestInstanceMetadataQueryBoundToExactInstance(t *testing.T) {
	a := domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-beijing", InstanceID: "i-target"}
	for _, returnedID := range []string{"i-target", "i-wrong", ""} {
		c := NewClient()
		calls := 0
		c.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("Action") != "DescribeInstances" || r.Form.Get("InstanceIds") != `["i-target"]` || r.Form.Get("RegionId") != "cn-beijing" {
				t.Fatal("incorrect request target")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"Instances":{"Instance":[{"InstanceId":%q,"InstanceChargeType":"PostPaid","SpotStrategy":"NoSpot"}]}}`, returnedID))), Header: make(http.Header), Request: r}, nil
		})}
		got, err := c.GetInstanceChargeType(context.Background(), a, "secret")
		if returnedID == a.InstanceID {
			if err != nil || got != "pay_as_you_go" {
				t.Fatalf("%s %v", got, err)
			}
		} else if err == nil || got != "unknown" {
			t.Fatal("accepted unrelated instance")
		}
		if calls != 1 {
			t.Fatal("unexpected retries")
		}
	}
	for _, ids := range []string{`[]`, `["i-one","i-two"]`, `["../bad"]`, `[null]`, `"i-one"`} {
		if validateAliyunExtras("DescribeInstances", map[string]string{"RegionId": "cn-beijing", "InstanceIds": ids}) == nil {
			t.Fatalf("accepted %s", ids)
		}
	}
	if validateAliyunExtras("StopInstance", map[string]string{"RegionId": "cn-beijing", "InstanceIds": `["i-one"]`}) == nil {
		t.Fatal("list filter leaked to control API")
	}
}

func TestInstanceMetadataIncludesValidatedAddressesFromSameResponse(t *testing.T) {
	account := domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-beijing", InstanceID: "i-target"}
	for _, tc := range []struct {
		name, addressJSON, ipv4, ipv6 string
	}{
		{"eip and ipv6", `"EipAddress":{"IpAddress":"203.0.113.7"},"Ipv6Address":{"Ipv6Address":["2001:db8::1"]}`, "203.0.113.7", "2001:db8::1"},
		{"public fallback", `"EipAddress":{"IpAddress":"bad"},"PublicIpAddress":{"IpAddress":["198.51.100.9"]},"Ipv6Address":"192.0.2.1"`, "198.51.100.9", ""},
		{"network interface", `"NetworkInterfaces":{"NetworkInterface":[{"Ipv6Sets":{"Ipv6Set":[{"Ipv6Address":"2001:db8::2"}]}}]}`, "", "2001:db8::2"},
		{"bad addresses", `"EipAddress":{"IpAddress":"2001:db8::1"},"Ipv6Address":"garbage"`, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := NewClient()
			calls := 0
			client.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				body := fmt.Sprintf(`{"Instances":{"Instance":[{"InstanceId":"i-target","InstanceChargeType":"PostPaid","SpotStrategy":"NoSpot",%s}]}}`, tc.addressJSON)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}, nil
			})}
			details, err := client.GetInstanceMetadata(context.Background(), account, "secret")
			if err != nil || details.ChargeType != "pay_as_you_go" || details.PublicIPv4 != tc.ipv4 || details.IPv6 != tc.ipv6 || calls != 1 {
				t.Fatalf("details=%+v calls=%d err=%v", details, calls, err)
			}
		})
	}
}
