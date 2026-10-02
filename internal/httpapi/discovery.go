package httpapi

import (
	"context"
	"github.com/wang4386/CDT-Monitor/internal/aliyun"
	"github.com/wang4386/CDT-Monitor/internal/domain"
	"net/http"
	"time"
)

type discoverInstancesRequest struct {
	SourceAccountID int64  `json:"source_account_id"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	RegionID        string `json:"region_id"`
	NextToken       string `json:"next_token"`
}

func (s *Server) discoverInstances(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate("discovery:"+clientIP(r), 30, time.Minute) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "查询过于频繁，请稍后再试")
		return
	}
	var req discoverInstancesRequest
	if err := decodeJSON(r, &req); err != nil || req.SourceAccountID < 0 || (req.SourceAccountID > 0 && req.AccessKeySecret != "") {
		writeError(w, http.StatusBadRequest, "invalid_request", "请选择已保存的凭据，或填写新的 AccessKey")
		return
	}
	secret := req.AccessKeySecret
	if req.SourceAccountID > 0 {
		var err error
		secret, err = s.store.AccountSecretForKey(r.Context(), req.SourceAccountID, req.AccessKeyID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "credential_unavailable", "原凭据已变化或不可用，请先保存设置后重新选择")
			return
		}
	}
	if !aliyun.ValidDiscoveryInput(req.AccessKeyID, secret, req.RegionID, req.NextToken) {
		writeError(w, http.StatusBadRequest, "invalid_request", "AccessKey、地域或分页参数无效")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	page, err := s.engine.DiscoverInstances(ctx, domain.Account{AccessKeyID: req.AccessKeyID, RegionID: req.RegionID}, secret, req.NextToken)
	if err != nil {
		writeError(w, http.StatusBadGateway, "discovery_failed", "无法获取实例，请检查凭据、该地域的 ecs:DescribeInstances 权限和网络后重试")
		return
	}
	writeJSON(w, http.StatusOK, page)
}
