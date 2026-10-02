package engine

import (
	"context"
	"errors"
	"github.com/wang4386/CDT-Monitor/internal/aliyun"
	"github.com/wang4386/CDT-Monitor/internal/domain"
)

func (e *Engine) DiscoverInstances(ctx context.Context, a domain.Account, secret, token string) (page aliyun.DiscoveryPage, err error) {
	defer func() {
		if recover() != nil {
			page = aliyun.DiscoveryPage{}
			err = errProviderPanic
		}
	}()
	provider, ok := e.provider.(aliyun.InstanceDiscoveryProvider)
	if !ok {
		return page, errors.New("instance discovery unavailable")
	}
	return provider.DiscoverInstances(ctx, a, secret, token)
}
