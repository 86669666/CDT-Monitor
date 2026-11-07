package httpapi

import (
	"database/sql"
	"errors"
	"net/http"
)

func (s *Server) pendingRecovery(w http.ResponseWriter, r *http.Request) {
	records, err := s.store.PendingRecovery(r.Context())
	if err != nil {
		writeError(w, 500, "recovery_failed", "待核对记录加载失败")
		return
	}
	for i := range records {
		records[i].Detail = s.redactSecrets(r.Context(), records[i].Detail)
	}
	writeJSON(w, 200, map[string]any{"records": records})
}

func (s *Server) resolveRecovery(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Note     string `json:"note"`
		Reviewed bool   `json:"reviewed"`
	}
	if err := decodeJSON(r, &input); err != nil || !input.Reviewed {
		writeError(w, 400, "review_required", "请先核对远端结果并明确确认")
		return
	}
	if err := s.engine.ResolveRecovery(r.Context(), r.PathValue("kind"), r.PathValue("id"), input.Note); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, 404, "record_not_found", "记录不存在或已核对")
			return
		}
		writeError(w, 400, "review_failed", "核对记录失败，请检查说明并刷新重试")
		return
	}
	writeJSON(w, 200, map[string]bool{"resolved": true})
}
