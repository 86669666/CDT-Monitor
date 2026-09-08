package engine

import (
	"context"
	"sync"

	"github.com/wang4386/CDT-Monitor/internal/aliyun"
	"github.com/wang4386/CDT-Monitor/internal/domain"
)

// fakeProvider is an offline Aliyun stand-in so engine tests never touch a real account.
type fakeProvider struct {
	mu         sync.Mutex
	traffic    float64
	status     string
	balance    aliyun.BillingBalance
	bill       aliyun.BillingBill
	controlErr error
	trafficErr error
	statusErr  error
	controls   []string
}

func newFakeProvider() *fakeProvider {
	return &fakeProvider{
		traffic: 1.25,
		status:  domain.StatusRunning,
		balance: aliyun.BillingBalance{Amount: 123.45, Currency: "CNY"},
		bill:    aliyun.BillingBill{TotalCost: 23.456},
	}
}

func (p *fakeProvider) GetTraffic(context.Context, domain.Account, string) (float64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.traffic, p.trafficErr
}

func (p *fakeProvider) GetInstanceStatus(context.Context, domain.Account, string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status, p.statusErr
}

func (p *fakeProvider) ControlInstance(_ context.Context, _ domain.Account, _ string, action, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.controls = append(p.controls, action)
	return p.controlErr
}

func (p *fakeProvider) GetAccountBalance(context.Context, domain.Account, string) (aliyun.BillingBalance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.balance, nil
}

func (p *fakeProvider) GetInstanceBill(context.Context, domain.Account, string, string) (aliyun.BillingBill, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bill, nil
}

func (p *fakeProvider) controlActions() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.controls...)
}
