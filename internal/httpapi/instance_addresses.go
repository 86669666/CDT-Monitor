package httpapi

import "net/http"

// instanceAddresses reads only cached data and is restricted to admin sessions.
func (s *Server) instanceAddresses(w http.ResponseWriter, r *http.Request) {
	items, err := s.engine.InstanceAddresses(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "instance_addresses_failed", "实例地址加载失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"instances": items})
}
