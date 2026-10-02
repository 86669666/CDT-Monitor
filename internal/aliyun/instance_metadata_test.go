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
