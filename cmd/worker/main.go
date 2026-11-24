package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"sentinel/internal/keystore"
	"sentinel/internal/worker"
)

func main() {
	apiURL := flag.String("api", "https://127.0.0.1:8443", "Sentinel API base URL")
	keys := flag.String("keys", "keys", "key directory (see cmd/keygen)")
	keyID := flag.String("key-id", "api-key-01", "API key id")
	workerID := flag.String("id", "worker-01", "worker id")
	mode := flag.String("mode", "secure", "secure | plain (plain = unprotected baseline, lab only)")
	targets := flag.String("targets", "example=https://example.com", "comma-separated name=url list")
	interval := flag.Duration("interval", 30*time.Second, "check interval")
	pin := flag.String("pin", "", "pinned SHA-256 fingerprint of the API public key (hex). Empty = trust-on-fetch (INSECURE)")
	pinFromKeys := flag.Bool("pin-from-keys", false, "derive the pin from <keys>/api/<key-id>.pub.pem (lab convenience)")
	caFile := flag.String("ca", "", "PEM CA/cert to trust for HTTPS (default <keys>/tls/cert.pem if it exists)")
	once := flag.Bool("once", false, "run one round and exit")
	flag.Parse()

	httpClient := &http.Client{Timeout: 10 * time.Second}
	ca := *caFile
	if ca == "" {
		if p := filepath.Join(*keys, "tls", "cert.pem"); fileExists(p) {
			ca = p
		}
	}
	if ca != "" {
		pemb, err := os.ReadFile(ca)
		if err != nil {
			log.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pemb)
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}

	cfg := worker.Config{
		APIURL: *apiURL, KeyID: *keyID, WorkerID: *workerID,
		Mode: worker.Mode(*mode), HTTP: httpClient, PinnedFingerprint: *pin,
	}
	if cfg.Mode == worker.ModeSecure {
		signer, err := keystore.LoadWorkerKey(*keys, *workerID)
		if err != nil {
			log.Fatal(err)
		}
		cfg.Signer = signer
		if *pinFromKeys {
			pub, err := keystore.LoadAPIPublicKey(*keys, *keyID)
			if err != nil {
				log.Fatal(err)
			}
			cfg.Recipient = pub // the pinned key itself; nothing is fetched
		}
	}
	if cfg.Mode == worker.ModeSecure && cfg.Recipient == nil && cfg.PinnedFingerprint == "" {
		log.Println("WARNING: no pin configured; the API public key is trusted on first fetch (vulnerable to key substitution)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	c, err := worker.New(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}

	var ts []worker.Target
	for _, kv := range strings.Split(*targets, ",") {
		name, u, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			log.Fatalf("bad target %q (want name=url)", kv)
		}
		ts = append(ts, worker.Target{Name: name, URL: u})
	}

	round := func() {
		for _, t := range ts {
			res := c.Check(ctx, t)
			info, err := c.Send(ctx, res)
			if err != nil {
				log.Printf("send %s failed: %v", t.Name, err)
				continue
			}
			log.Printf("sent %s status=%s code=%d rt=%dms bytes=%d", res.Service, res.Status, res.StatusCode, res.ResponseTimeMS, info.BytesSent)
		}
	}
	round()
	if *once {
		return
	}
	tk := time.NewTicker(*interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			round()
		}
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
