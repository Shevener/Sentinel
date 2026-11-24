package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"sentinel/internal/api"
	"sentinel/internal/keystore"
	"sentinel/internal/security"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "listen address")
	keys := flag.String("keys", "keys", "key directory (see cmd/keygen)")
	useTLS := flag.Bool("tls", true, "serve HTTPS using <keys>/tls/{cert,key}.pem")
	allowPlain := flag.Bool("allow-plain", false, "enable UNPROTECTED baseline endpoint (lab only)")
	fresh := flag.Duration("freshness", 5*time.Minute, "timestamp freshness window")
	flag.Parse()

	apiKeys, err := keystore.LoadAPIKeys(*keys)
	if err != nil {
		log.Fatal(err)
	}
	workers, err := keystore.LoadTrustedWorkers(*keys)
	if err != nil {
		log.Fatal(err)
	}
	srv := api.New(api.Config{
		Keys:       apiKeys,
		Workers:    workers,
		Guard:      security.NewReplayGuard(*fresh, security.DefaultSeqWindow),
		AllowPlain: *allowPlain,
		AdminToken: os.Getenv("SENTINEL_ADMIN_TOKEN"),
	})
	if os.Getenv("SENTINEL_ADMIN_TOKEN") == "" {
		log.Println("WARNING: SENTINEL_ADMIN_TOKEN not set; read endpoints are open (lab only)")
	}
	if *allowPlain {
		log.Println("WARNING: baseline plain endpoint enabled (lab only)")
	}

	hs := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	log.Printf("sentinel-api listening on %s (tls=%v, keys=%d, trusted workers=%d)", *addr, *useTLS, len(apiKeys), len(workers))
	if *useTLS {
		log.Fatal(hs.ListenAndServeTLS(filepath.Join(*keys, "tls", "cert.pem"), filepath.Join(*keys, "tls", "key.pem")))
	}
	log.Fatal(hs.ListenAndServe())
}
