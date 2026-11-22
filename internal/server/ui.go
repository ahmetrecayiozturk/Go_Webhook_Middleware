package server

import (
	"embed"
	"net/http"
)

//go:embed ui/index.html
var adminUIFS embed.FS

func HandleAdminUI(w http.ResponseWriter, r *http.Request) {
	data, err := adminUIFS.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "Admin UI yüklenemedi", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
