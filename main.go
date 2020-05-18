package main

import (
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi"
)

// App contains the global app context and config.
type App struct {
	SSORootURL string
	SSOSecret  []byte
	APIKey     string
	APISecret  string
}

func main() {
	app := &App{
		SSORootURL: os.Getenv("SSO_ROOT_URL"),
		SSOSecret:  []byte(os.Getenv("SSO_SECRET")),
		APIKey:     os.Getenv("KITE_KEY"),
		APISecret:  os.Getenv("KITE_SECRET"),
	}
	if len(app.SSORootURL) == 0 || len(app.SSOSecret) == 0 || len(app.APIKey) == 0 || len(app.APISecret) == 0 {
		log.Fatal("missing env vars: SSO_ROOT_URL / SSO_SECRET / KITE_KEY / KITE_SECRET")
	}

	// Start the HTTP server.
	addr := os.Getenv("KITE_ADDRESS")
	if addr == "" {
		addr = ":9000"
	}

	r := chi.NewRouter()
	r.Get("/kite/auth", wrap(handleAuthInit, app))
	r.Get("/kite/auth/finish", wrap(handleAuthFinish, app))

	log.Printf("listening on (KITE_ADDRESS): %s", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}
