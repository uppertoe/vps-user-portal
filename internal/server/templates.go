package server

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
)

//go:embed templates/*.html templates/style.css
var templateFS embed.FS

var pages = template.Must(template.ParseFS(templateFS, "templates/base.html", "templates/*.html"))

// render executes one page template. Every page gets the acting admin and a
// fresh CSRF token bound to them.
func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	id := actor(r)
	data["Actor"] = id.User
	data["CSRF"] = csrfToken(s.cfg.CSRFSecret, id.User, s.now())
	data["Page"] = page

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages.ExecuteTemplate(w, page, data); err != nil {
		slog.Error("template render failed", "page", page, "err", err)
	}
}

func handleCSS(w http.ResponseWriter, _ *http.Request) {
	b, _ := templateFS.ReadFile("templates/style.css")
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(b)
}
