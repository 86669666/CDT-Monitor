package aliyun

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/wang4386/CDT-Monitor/internal/domain"
)

func TestTrafficClass(t *testing.T) {
	cases := map[string]string{
		"cn-hangzhou":    "china",
		"cn-shanghai":    "china",
		"cn-hongkong":    "international",
		"ap-southeast-1": "international",
		"ap-northeast-1": "international",
		"ap-northeast-2": "international",
	}
	for region, expected := range cases {
		if actual := trafficClass(region); actual != expected {
			t.Fatalf("%s: got %s", region, actual)
		}
	}
}

func TestBssEndpoints(t *testing.T) {
	if endpoint := bssEndpoint("china"); endpoint.host != "business.aliyuncs.com" || endpoint.region != "cn-hangzhou" {
		t.Fatalf("unexpected China endpoint: %#v", endpoint)
	}
	if endpoint := bssEndpoint("international"); endpoint.host != "business.ap-southeast-1.aliyuncs.com" || endpoint.region != "ap-southeast-1" {
		t.Fatalf("unexpected international endpoint: %#v", endpoint)
	}
}

func TestTrafficResponseAggregation(t *testing.T) {
	result := map[string]any{"TrafficDetails": []any{
		map[string]any{"BusinessRegionId": "cn-hangzhou", "Traffic": float64(1024 * 1024 * 1024)},
		map[string]any{"BusinessRegionId": "cn-beijing", "Traffic": float64(2 * 1024 * 1024 * 1024)},
		map[string]any{"BusinessRegionId": "cn-hongkong", "Traffic": float64(4 * 1024 * 1024 * 1024)},
	}}
	traffic, err := trafficFromResponse(result, "china")
	if err != nil || traffic != 3 {
		t.Fatalf("traffic=%v err=%v", traffic, err)
	}
}

func TestAsSliceSupportsSingleBssItem(t *testing.T) {
	items := asSlice(map[string]any{"Item": map[string]any{"PretaxAmount": "23.456"}})
	if len(items) != 1 {
		t.Fatalf("expected one BSS item, got %#v", items)
	}
	item, ok := items[0].(map[string]any)
	if !ok || number(item["PretaxAmount"]) != 23.456 {
		t.Fatalf("unexpected BSS item: %#v", items[0])
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestGetAccountBalanceAcceptsAliyunBusinessCode200(t *testing.T) {
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"Code":"200","Message":"success","Data":{"AvailableAmount":"123.45"}}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}

	balance, err := client.GetAccountBalance(context.Background(), domain.Account{AccessKeyID: "LTAItest", SiteType: "china"}, "secret")
	if err != nil || balance.Amount != 123.45 || balance.Currency != "CNY" {
		t.Fatalf("balance=%#v err=%v", balance, err)
	}
}

func TestCallErrorsRedactAccessKeyMaterial(t *testing.T) {
	secret := "super-secret-ak-value"
	accessKeyID := "LTAIleakkey"
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       io.NopCloser(strings.NewReader(`{"Code":"InvalidAccessKeyId","Message":"AccessKeyId ` + accessKeyID + ` secret ` + secret + ` rejected"}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	_, err := client.GetTraffic(context.Background(), domain.Account{AccessKeyID: accessKeyID, RegionID: "cn-hongkong"}, secret)
	if err == nil {
		t.Fatal("expected Aliyun error")
	}
	msg := err.Error()
	if strings.Contains(msg, secret) || strings.Contains(msg, accessKeyID) {
		t.Fatalf("error leaked credentials: %q", msg)
	}
	if !strings.Contains(msg, "[redacted]") || !strings.Contains(msg, "LTAIlea***") {
		t.Fatalf("expected redaction markers in %q", msg)
	}
}

func TestCallRetriesServerErrorThenSucceeds(t *testing.T) {
	var hits int
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		hits++
		if hits == 1 {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader(`{"Code":"InternalError","Message":"try again"}`)),
				Header:     make(http.Header),
				Request:    request,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"Code":"200","Message":"success","Data":{"AvailableAmount":"12.5"}}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	balance, err := client.GetAccountBalance(context.Background(), domain.Account{AccessKeyID: "LTAItest", SiteType: "china"}, "secret")
	if err != nil || balance.Amount != 12.5 {
		t.Fatalf("balance=%#v err=%v", balance, err)
	}
	if hits != 2 {
		t.Fatalf("hits = %d", hits)
	}
}

func TestCallDoesNotRetryClientErrors(t *testing.T) {
	var hits int
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		hits++
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(strings.NewReader(`{"Code":"InvalidParameter","Message":"bad request"}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	_, err := client.GetAccountBalance(context.Background(), domain.Account{AccessKeyID: "LTAItest", SiteType: "china"}, "secret")
	if err == nil || !strings.Contains(err.Error(), "bad request") {
		t.Fatalf("err = %v", err)
	}
	if hits != 1 {
		t.Fatalf("client error should not retry, hits = %d", hits)
	}
}

func TestControlInstanceRequiresInstanceID(t *testing.T) {
	var hits int
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		hits++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header), Request: request}, nil
	})}
	err := client.ControlInstance(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-hongkong"}, "secret", "start", "KeepCharging")
	if err == nil || hits != 0 {
		t.Fatalf("empty instance_id err=%v hits=%d", err, hits)
	}
}

func TestGetInstanceStatusFromDescribeResponse(t *testing.T) {
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"InstanceStatuses":{"InstanceStatus":[{"InstanceId":"i-test","Status":"Running"}]}}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	status, err := client.GetInstanceStatus(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-hongkong", InstanceID: "i-test"}, "secret")
	if err != nil || status != domain.StatusRunning {
		t.Fatalf("status=%q err=%v", status, err)
	}
}

func TestControlInstanceStopDefaultsToKeepCharging(t *testing.T) {
	var action, mode string
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		values, _ := url.ParseQuery(string(body))
		action, mode = values.Get("Action"), values.Get("StoppedMode")
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header), Request: request}, nil
	})}
	if err := client.ControlInstance(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-hongkong", InstanceID: "i-test"}, "secret", "STOP", ""); err != nil {
		t.Fatal(err)
	}
	if action != "StopInstance" || mode != "KeepCharging" {
		t.Fatalf("Action=%q StoppedMode=%q", action, mode)
	}
}

func TestCallRetriesTooManyRequestsThenSucceeds(t *testing.T) {
	var hits int
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		hits++
		if hits == 1 {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Body:       io.NopCloser(strings.NewReader(`{"Code":"Throttling","Message":"slow down"}`)),
				Header:     make(http.Header),
				Request:    request,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"Code":"200","Message":"success","Data":{"AvailableAmount":"8.25"}}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	balance, err := client.GetAccountBalance(context.Background(), domain.Account{AccessKeyID: "LTAItest", SiteType: "china"}, "secret")
	if err != nil || balance.Amount != 8.25 {
		t.Fatalf("balance=%#v err=%v", balance, err)
	}
	if hits != 2 {
		t.Fatalf("hits = %d", hits)
	}
}

func TestGetTrafficUsesMockCdtAndCaches(t *testing.T) {
	var hits int
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		hits++
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(`{"TrafficDetails":[
				{"BusinessRegionId":"cn-hangzhou","Traffic":1073741824},
				{"BusinessRegionId":"cn-beijing","Traffic":2147483648},
				{"BusinessRegionId":"cn-hongkong","Traffic":4294967296}
			]}`)),
			Header:  make(http.Header),
			Request: request,
		}, nil
	})}
	account := domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-hangzhou"}
	first, err := client.GetTraffic(context.Background(), account, "secret")
	if err != nil || first != 3 {
		t.Fatalf("first traffic=%v err=%v", first, err)
	}
	second, err := client.GetTraffic(context.Background(), account, "secret")
	if err != nil || second != 3 {
		t.Fatalf("cached traffic=%v err=%v", second, err)
	}
	if hits != 1 {
		t.Fatalf("expected one CDT call, hits=%d", hits)
	}
}

func TestGetInstanceBillSumsPretaxAmount(t *testing.T) {
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"Data":{"Items":{"Item":[{"PretaxAmount":"10.5"},{"PretaxAmount":"12.96"}]}}}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	bill, err := client.GetInstanceBill(context.Background(), domain.Account{AccessKeyID: "LTAItest", SiteType: "china", InstanceID: "i-test"}, "secret", "2026-09")
	if err != nil || bill.TotalCost != 23.46 {
		t.Fatalf("bill=%#v err=%v", bill, err)
	}
}

func TestGetAccountBalanceCachesForSixHours(t *testing.T) {
	var hits int
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		hits++
		if request.URL.Host != "business.aliyuncs.com" {
			t.Errorf("host = %s", request.URL.Host)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"Code":"200","Data":{"AvailableAmount":"50","Currency":"CNY"}}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	account := domain.Account{AccessKeyID: "LTAItest", SiteType: "china"}
	first, err := client.GetAccountBalance(context.Background(), account, "secret")
	if err != nil || first.Amount != 50 || first.Currency != "CNY" {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	second, err := client.GetAccountBalance(context.Background(), account, "secret")
	if err != nil || second.Amount != 50 {
		t.Fatalf("cached=%#v err=%v", second, err)
	}
	if hits != 1 {
		t.Fatalf("hits = %d", hits)
	}
}

func TestGetAccountBalanceUsesInternationalEndpoint(t *testing.T) {
	var host string
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		host = request.URL.Host
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"Code":"200","Data":{"AvailableAmount":"1.5","Currency":"USD"}}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	balance, err := client.GetAccountBalance(context.Background(), domain.Account{AccessKeyID: "LTAItest", SiteType: "international"}, "secret")
	if err != nil || balance.Amount != 1.5 || balance.Currency != "USD" {
		t.Fatalf("balance=%#v err=%v", balance, err)
	}
	if host != "business.ap-southeast-1.aliyuncs.com" {
		t.Fatalf("host = %s", host)
	}
}

func TestControlInstanceStartSendsStartInstance(t *testing.T) {
	var action, mode string
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		values, _ := url.ParseQuery(string(body))
		action, mode = values.Get("Action"), values.Get("StoppedMode")
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header), Request: request}, nil
	})}
	if err := client.ControlInstance(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-hongkong", InstanceID: "i-test"}, "secret", "start", "KeepCharging"); err != nil {
		t.Fatal(err)
	}
	if action != "StartInstance" || mode != "" {
		t.Fatalf("Action=%q StoppedMode=%q", action, mode)
	}
}

func TestGetTrafficMissingDetailsIsError(t *testing.T) {
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"Code":"200","TrafficDetails":[]}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	_, err := client.GetTraffic(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-hangzhou"}, "secret")
	if err == nil || !strings.Contains(err.Error(), "TrafficDetails") {
		t.Fatalf("err = %v", err)
	}
}

func TestControlInstanceStopChargingMode(t *testing.T) {
	var action, mode string
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		values, _ := url.ParseQuery(string(body))
		action, mode = values.Get("Action"), values.Get("StoppedMode")
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header), Request: request}, nil
	})}
	if err := client.ControlInstance(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-hongkong", InstanceID: "i-test"}, "secret", "stop", "StopCharging"); err != nil {
		t.Fatal(err)
	}
	if action != "StopInstance" || mode != "StopCharging" {
		t.Fatalf("Action=%q StoppedMode=%q", action, mode)
	}
}

func TestCallTruncatesNonJSONErrorBodies(t *testing.T) {
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(strings.NewReader(`{"Code":"Error","Pad":"` + strings.Repeat("A", 400) + `"}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	_, err := client.GetAccountBalance(context.Background(), domain.Account{AccessKeyID: "LTAItest", SiteType: "china"}, "secret")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "...") || len(msg) > 320 {
		t.Fatalf("expected truncated error, got len=%d %q", len(msg), msg)
	}
}

func TestGetTrafficInternationalExcludesChina(t *testing.T) {
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(`{"TrafficDetails":[
				{"BusinessRegionId":"cn-hangzhou","Traffic":1073741824},
				{"BusinessRegionId":"cn-hongkong","Traffic":4294967296}
			]}`)),
			Header:  make(http.Header),
			Request: request,
		}, nil
	})}
	traffic, err := client.GetTraffic(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-hongkong"}, "secret")
	if err != nil || traffic != 4 {
		t.Fatalf("traffic=%v err=%v", traffic, err)
	}
}

func TestCallRetriesThrottlingCodeThenSucceeds(t *testing.T) {
	var hits int
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		hits++
		if hits == 1 {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"Code":"Throttling.User","Message":"slow down"}`)),
				Header:     make(http.Header),
				Request:    request,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"Code":"200","Data":{"AvailableAmount":"3.5"}}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	balance, err := client.GetAccountBalance(context.Background(), domain.Account{AccessKeyID: "LTAItest", SiteType: "china"}, "secret")
	if err != nil || balance.Amount != 3.5 {
		t.Fatalf("balance=%#v err=%v", balance, err)
	}
	if hits != 2 {
		t.Fatalf("hits = %d", hits)
	}
}

func TestGetInstanceStatusEmptyIsUnknown(t *testing.T) {
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"InstanceStatuses":{"InstanceStatus":[]}}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	status, err := client.GetInstanceStatus(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-hongkong", InstanceID: "i-missing"}, "secret")
	if err != nil || status != domain.StatusUnknown {
		t.Fatalf("status=%q err=%v", status, err)
	}
}

func TestGetTrafficTokyoIsInternational(t *testing.T) {
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(`{"TrafficDetails":[
				{"BusinessRegionId":"cn-hangzhou","Traffic":1073741824},
				{"BusinessRegionId":"ap-northeast-1","Traffic":3221225472}
			]}`)),
			Header:  make(http.Header),
			Request: request,
		}, nil
	})}
	traffic, err := client.GetTraffic(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "ap-northeast-1"}, "secret")
	if err != nil || traffic != 3 {
		t.Fatalf("tokyo traffic=%v err=%v", traffic, err)
	}
}

func TestGetTrafficShanghaiIsChina(t *testing.T) {
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(`{"TrafficDetails":[
				{"BusinessRegionId":"cn-hangzhou","Traffic":1073741824},
				{"BusinessRegionId":"cn-shanghai","Traffic":2147483648},
				{"BusinessRegionId":"cn-hongkong","Traffic":4294967296}
			]}`)),
			Header:  make(http.Header),
			Request: request,
		}, nil
	})}
	traffic, err := client.GetTraffic(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-shanghai"}, "secret")
	if err != nil || traffic != 3 {
		t.Fatalf("shanghai traffic=%v err=%v", traffic, err)
	}
}

func TestGetTrafficSeoulIsInternational(t *testing.T) {
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(`{"TrafficDetails":[
				{"BusinessRegionId":"cn-hangzhou","Traffic":1073741824},
				{"BusinessRegionId":"ap-northeast-2","Traffic":2147483648}
			]}`)),
			Header:  make(http.Header),
			Request: request,
		}, nil
	})}
	traffic, err := client.GetTraffic(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "ap-northeast-2"}, "secret")
	if err != nil || traffic != 2 {
		t.Fatalf("seoul traffic=%v err=%v", traffic, err)
	}
}

func TestGetInstanceStatusAcceptsSingleObject(t *testing.T) {
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"InstanceStatuses":{"InstanceStatus":{"InstanceId":"i-test","Status":"Stopped"}}}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	status, err := client.GetInstanceStatus(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-hongkong", InstanceID: "i-test"}, "secret")
	if err != nil || status != domain.StatusStopped {
		t.Fatalf("status=%q err=%v", status, err)
	}
}

func TestGetTrafficAcceptsSingleTrafficDetailsObject(t *testing.T) {
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"TrafficDetails":{"BusinessRegionId":"cn-hangzhou","Traffic":1073741824}}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	traffic, err := client.GetTraffic(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-hangzhou"}, "secret")
	if err != nil || traffic != 1 {
		t.Fatalf("traffic=%v err=%v", traffic, err)
	}
}

func TestGetTrafficCacheIsPerAccessKey(t *testing.T) {
	var hits int
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		hits++
		body, _ := io.ReadAll(request.Body)
		values, _ := url.ParseQuery(string(body))
		traffic := "1073741824"
		if values.Get("AccessKeyId") == "LTAItwo" {
			traffic = "2147483648"
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"TrafficDetails":[{"BusinessRegionId":"cn-hangzhou","Traffic":` + traffic + `}]}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	one, err := client.GetTraffic(context.Background(), domain.Account{AccessKeyID: "LTAIone", RegionID: "cn-hangzhou"}, "secret")
	if err != nil || one != 1 {
		t.Fatalf("one=%v err=%v", one, err)
	}
	two, err := client.GetTraffic(context.Background(), domain.Account{AccessKeyID: "LTAItwo", RegionID: "cn-hangzhou"}, "secret")
	if err != nil || two != 2 {
		t.Fatalf("two=%v err=%v", two, err)
	}
	if hits != 2 {
		t.Fatalf("expected per-key CDT calls, hits=%d", hits)
	}
}

func TestGetTrafficCacheIsPerTrafficClass(t *testing.T) {
	var hits int
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		hits++
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(`{"TrafficDetails":[
				{"BusinessRegionId":"cn-hangzhou","Traffic":1073741824},
				{"BusinessRegionId":"cn-shanghai","Traffic":2147483648},
				{"BusinessRegionId":"cn-hongkong","Traffic":4294967296}
			]}`)),
			Header:  make(http.Header),
			Request: request,
		}, nil
	})}
	china, err := client.GetTraffic(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-hangzhou"}, "secret")
	if err != nil || china != 3 {
		t.Fatalf("hangzhou traffic=%v err=%v", china, err)
	}
	international, err := client.GetTraffic(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-hongkong"}, "secret")
	if err != nil || international != 4 {
		t.Fatalf("hongkong traffic=%v err=%v", international, err)
	}
	if hits != 2 {
		t.Fatalf("china and international caches must be distinct, hits=%d", hits)
	}
	shanghai, err := client.GetTraffic(context.Background(), domain.Account{AccessKeyID: "LTAItest", RegionID: "cn-shanghai"}, "secret")
	if err != nil || shanghai != 3 {
		t.Fatalf("shanghai cached traffic=%v err=%v", shanghai, err)
	}
	if hits != 2 {
		t.Fatalf("same-class regions should share the cache, hits=%d", hits)
	}
}
