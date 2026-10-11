// Package ui serves the local dashboard embedded in the agent binary.
//
// dist/ is the static export of the dashboard (xytherion site repo:
// `npm run build:agent-ui`). It is committed so `go build` needs no Node.js.
package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// "all:" is required: without it go:embed skips names starting with "_",
// which would drop the whole _next/ asset folder.
//
//go:embed all:dist
var dist embed.FS

// Handler serves the dashboard. Hashed assets under /_next/static/ are cached
// forever; pages are revalidated so an agent update shows the new UI at once.
func Handler() http.Handler {
	root, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // dist is embedded at build time; this cannot fail at runtime
	}
	files := http.FileServer(http.FS(root))
	notFound, _ := fs.ReadFile(root, "404.html")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" {
			name = "."
		}
		if !exists(root, name) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			w.Write(notFound)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/_next/static/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

func exists(root fs.FS, name string) bool {
	if _, err := fs.Stat(root, name); err == nil {
		return true
	}
	// Directory URLs such as /status/ resolve to status/index.html.
	_, err := fs.Stat(root, path.Join(name, "index.html"))
	return err == nil
}
