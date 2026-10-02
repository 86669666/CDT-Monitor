package aliyun

import (
	"context"
	"github.com/wang4386/CDT-Monitor/internal/domain"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDiscoveryFixedPaginationAndProjection(t *testing.T) {
	c := NewClient()
	calls := 0
	c.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		_ = r.ParseForm()
		if r.Form.Get("Action") != "DescribeInstances" || r.Form.Get("MaxResults") != "50" || r.Form.Get("NextToken") != "opaque-next==" || r.Form.Get("InstanceIds") != "" || r.URL.Host != "ecs.cn-beijing.aliyuncs.com" {
			t.Fatal("invalid discovery request")
		}
		body := `{"Instances":{"Instance":[{"InstanceId":"i-one","InstanceName":"Web\nserver","RegionId":"cn-beijing","Status":"Running","InstanceChargeType":"PostPaid","SpotStrategy":"NoSpot","PrivateIpAddress":"sensitive-ignored"}]},"NextToken":"opaque-more"}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}, nil
	})}
	page, err := c.DiscoverInstances(t.Context(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-beijing"}, "secret", "opaque-next==")
	if err != nil || calls != 1 || len(page.Instances) != 1 || page.NextToken != "opaque-more" || page.Instances[0].ChargeType != "pay_as_you_go" || page.Instances[0].InstanceName != "Webserver" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
}

func TestDiscoveryRejectsMalformedOrMismatchedResponses(t *testing.T) {
	for _, body := range []string{
		`{}`, `{"Instances":{}}`,
		`{"Instances":{"Instance":[{"InstanceId":"i-one","RegionId":"cn-hongkong"}]}}`,
		`{"Instances":{"Instance":[{"InstanceId":"bad/id","RegionId":"cn-beijing"}]}}`,
		`{"Instances":{"Instance":[]},"NextToken":"same"}`,
		`{"Instances":{"Instance":[]},"NextToken":123}`,
		`{"Instances":{"Instance":[]},"NextToken":"bad\ntoken"}`,
	} {
		c := NewClient()
		c.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}, nil
		})}
		if _, err := c.DiscoverInstances(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-beijing"}, "secret", "same"); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}

func TestDiscoveryWhitelistShapes(t *testing.T) {
	for _, extra := range []map[string]string{
		{"RegionId": "cn-beijing", "InstanceIds": `["i-one"]`},
		{"RegionId": "cn-beijing", "MaxResults": "50"},
		{"RegionId": "cn-beijing", "MaxResults": "50", "NextToken": "opaque=="},
	} {
		if err := validateAliyunExtras("DescribeInstances", extra); err != nil {
			t.Fatal(err)
		}
	}
	for _, extra := range []map[string]string{
		{"RegionId": "cn-beijing"},
		{"RegionId": "cn-beijing", "InstanceIds": `["i-one"]`, "MaxResults": "50"},
		{"RegionId": "cn-beijing", "InstanceIds": `["i-one"]`, "NextToken": "token"},
		{"RegionId": "cn-beijing", "NextToken": "token"},
		{"RegionId": "cn-beijing", "MaxResults": "100"},
		{"RegionId": "cn-beijing", "MaxResults": "50", "Host": "attacker.example"},
		{"RegionId": "cn-beijing", "MaxResults": "50", "NextToken": strings.Repeat("x", 2049)},
		{"RegionId": "cn-beijing", "MaxResults": "50", "NextToken": "bad token"},
	} {
		if err := validateAliyunExtras("DescribeInstances", extra); err == nil {
			t.Fatalf("accepted %+v", extra)
		}
	}
	for _, action := range []string{"StartInstance", "StopInstance", "ListCdtInternetTraffic"} {
		if validateAliyunExtras(action, map[string]string{"RegionId": "cn-beijing", "MaxResults": "50"}) == nil {
			t.Fatal("pagination escaped discovery")
		}
	}
}
