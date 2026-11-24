// bench measures end-to-end Worker→API communication in two modes over
// HTTPS: baseline (no application-layer crypto) and secure (RSA-OAEP +
// AES-256-GCM + RSA-PSS envelope). The API runs as a separate OS process so
// its CPU time and peak memory can be read from /proc.
//
// Raw per-run data goes to results/e2e_raw.csv; summary to results/e2e_summary.md.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"sentinel/internal/keystore"
	"sentinel/internal/monitoring"
	"sentinel/internal/worker"
)

type run struct {
	Trial, Conc, Requests, Errors int
	Mode                          string
	DurationS, Throughput         float64
	MeanMS, P50MS, P95MS, P99MS   float64
	EncryptMeanUS                 float64
	APICPUMS, ClientCPUMS         float64
	APIPeakRSSKB                  int
	BytesTotal                    int64
	BytesPerReq                   float64
}

func main() {
	apiBin := flag.String("api-bin", "bin/api", "path to API binary")
	keys := flag.String("keys", "keys", "key directory")
	trials := flag.Int("trials", 8, "trials per (mode, concurrency)")
	requests := flag.Int("requests", 1000, "measured requests per run")
	requestsPlain := flag.Int("requests-plain", 20000, "measured requests per baseline run")
	warmup := flag.Int("warmup", 100, "warm-up requests per run (discarded)")
	concList := flag.String("conc", "1,8", "comma-separated client concurrency levels")
	apiCPU := flag.String("api-cpu", "0", "CPU core to pin the API process to (taskset); empty = no pinning")
	out := flag.String("out", "results", "output directory")
	flag.Parse()

	var concs []int
	for _, s := range strings.Split(*concList, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			log.Fatal(err)
		}
		concs = append(concs, n)
	}

	signer, err := keystore.LoadWorkerKey(*keys, "worker-01")
	if err != nil {
		log.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(*keys, "tls", "cert.pem"))
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	var runs []run
	for _, conc := range concs {
		for t := 1; t <= *trials; t++ {
			modes := []worker.Mode{worker.ModePlain, worker.ModeSecure}
			if t%2 == 0 { // alternate order to cancel drift
				modes = []worker.Mode{worker.ModeSecure, worker.ModePlain}
			}
			for _, m := range modes {
				nReq := *requests
				if m == worker.ModePlain {
					nReq = *requestsPlain // baseline is ~50x faster; needs more requests for a measurable CPU time
				}
				r, err := oneRun(*apiBin, *keys, *apiCPU, signer, pool, m, conc, nReq, *warmup)
				if err != nil {
					log.Fatalf("trial %d %s conc=%d: %v", t, m, conc, err)
				}
				r.Trial = t
				runs = append(runs, r)
				fmt.Printf("trial %d conc=%d %-6s  %7.1f req/s  mean %.2f ms  p95 %.2f ms  api_cpu/req %.2f ms  errors %d\n",
					t, conc, m, r.Throughput, r.MeanMS, r.P95MS, r.APICPUMS/float64(r.Requests), r.Errors)
			}
		}
	}
	write(*out, runs, *requests, *warmup, *apiCPU)
}

func freePort() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func procCPUMS(pid int) float64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(b)
	s = s[strings.LastIndex(s, ")")+2:] // skip pid and (comm)
	f := strings.Fields(s)
	ut, _ := strconv.ParseFloat(f[11], 64) // utime (field 14 overall)
	st, _ := strconv.ParseFloat(f[12], 64) // stime
	return (ut + st) * 1000 / 100          // CLK_TCK = 100
}

func procStatusKB(pid int, key string) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, key+":") {
			f := strings.Fields(line)
			n, _ := strconv.Atoi(f[1])
			return n
		}
	}
	return 0
}

func selfCPUMS() float64 {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return float64(ru.Utime.Sec+ru.Stime.Sec)*1000 + float64(ru.Utime.Usec+ru.Stime.Usec)/1000
}

func oneRun(apiBin, keys, apiCPU string, signer interface{}, pool *x509.CertPool, mode worker.Mode, conc, n, warm int) (run, error) {
	addr := freePort()
	args := []string{apiBin, "-addr", addr, "-keys", keys, "-tls=true", "-allow-plain"}
	var cmd *exec.Cmd
	if apiCPU != "" {
		cmd = exec.Command("taskset", append([]string{"-c", apiCPU}, args...)...)
	} else {
		cmd = exec.Command(args[0], args[1:]...)
	}
	cmd.Env = append(os.Environ(), "SENTINEL_ADMIN_TOKEN=bench")
	if err := cmd.Start(); err != nil {
		return run{}, err
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	pid := cmd.Process.Pid

	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		MaxIdleConnsPerHost: conc * 2,
		MaxIdleConns:        conc * 2,
	}
	hc := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	base := "https://" + addr

	// wait for readiness
	ready := false
	for i := 0; i < 100; i++ {
		resp, err := hc.Get(base + "/healthz")
		if err == nil {
			resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		return run{}, fmt.Errorf("API did not become ready")
	}

	ctx := context.Background()
	cfg := worker.Config{APIURL: base, KeyID: "api-key-01", WorkerID: "worker-01", Mode: mode, HTTP: hc}
	if mode == worker.ModeSecure {
		sk, err := keystore.LoadWorkerKey(keys, "worker-01")
		if err != nil {
			return run{}, err
		}
		cfg.Signer = sk
		pub, err := keystore.LoadAPIPublicKey(keys, "api-key-01")
		if err != nil {
			return run{}, err
		}
		cfg.Recipient = pub
	}
	c, err := worker.New(ctx, cfg)
	if err != nil {
		return run{}, err
	}
	res := monitoring.Result{Service: "payment-api", Status: "down", StatusCode: 503, ResponseTimeMS: 842, CheckedAt: time.Now().UTC()}

	drive := func(total int) (lat []float64, enc []float64, bytes int64, errs int) {
		var mu sync.Mutex
		var wg sync.WaitGroup
		per := total / conc
		for g := 0; g < conc; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				l := make([]float64, 0, per)
				e := make([]float64, 0, per)
				var b int64
				var er int
				for i := 0; i < per; i++ {
					t0 := time.Now()
					info, err := c.Send(ctx, res)
					d := time.Since(t0)
					if err != nil {
						er++
						continue
					}
					l = append(l, float64(d.Nanoseconds())/1e6)
					e = append(e, float64(info.EncryptNS)/1e3)
					b += int64(info.BytesSent)
				}
				mu.Lock()
				lat = append(lat, l...)
				enc = append(enc, e...)
				bytes += b
				errs += er
				mu.Unlock()
			}()
		}
		wg.Wait()
		return
	}

	drive(warm)

	cpuA0, cpuC0 := procCPUMS(pid), selfCPUMS()
	t0 := time.Now()
	lat, enc, bytes, errs := drive(n)
	dur := time.Since(t0).Seconds()
	cpuA1, cpuC1 := procCPUMS(pid), selfCPUMS()
	hwm := procStatusKB(pid, "VmHWM")

	if len(lat) == 0 {
		return run{}, fmt.Errorf("no successful requests (errors=%d)", errs)
	}
	sort.Float64s(lat)
	pct := func(p float64) float64 {
		return lat[int(math.Min(float64(len(lat)-1), math.Floor(p*float64(len(lat)))))]
	}
	mean := func(v []float64) float64 {
		if len(v) == 0 {
			return 0
		}
		var s float64
		for _, x := range v {
			s += x
		}
		return s / float64(len(v))
	}
	done := len(lat)
	return run{
		Mode: string(mode), Conc: conc, Requests: done, Errors: errs,
		DurationS: dur, Throughput: float64(done) / dur,
		MeanMS: mean(lat), P50MS: pct(0.50), P95MS: pct(0.95), P99MS: pct(0.99),
		EncryptMeanUS: mean(enc),
		APICPUMS:      cpuA1 - cpuA0, ClientCPUMS: cpuC1 - cpuC0,
		APIPeakRSSKB: hwm, BytesTotal: bytes, BytesPerReq: float64(bytes) / float64(done),
	}, nil
}

// ---- output -----------------------------------------------------------

func write(dir string, runs []run, n, warm int, apiCPU string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "e2e_raw.csv"))
	if err != nil {
		log.Fatal(err)
	}
	cw := csv.NewWriter(f)
	_ = cw.Write([]string{"trial", "mode", "concurrency", "requests", "errors", "duration_s", "throughput_rps", "mean_ms", "p50_ms", "p95_ms", "p99_ms",
		"client_encrypt_mean_us", "api_cpu_ms", "client_cpu_ms", "api_peak_rss_kb", "bytes_total", "bytes_per_req"})
	ff := func(v float64) string { return strconv.FormatFloat(v, 'f', 4, 64) }
	for _, r := range runs {
		_ = cw.Write([]string{strconv.Itoa(r.Trial), r.Mode, strconv.Itoa(r.Conc), strconv.Itoa(r.Requests), strconv.Itoa(r.Errors),
			ff(r.DurationS), ff(r.Throughput), ff(r.MeanMS), ff(r.P50MS), ff(r.P95MS), ff(r.P99MS), ff(r.EncryptMeanUS),
			ff(r.APICPUMS), ff(r.ClientCPUMS), strconv.Itoa(r.APIPeakRSSKB), strconv.FormatInt(r.BytesTotal, 10), ff(r.BytesPerReq)})
	}
	cw.Flush()
	f.Close()

	type agg struct {
		Mode string
		Conc int
		N    int
		M    map[string][2]float64 // metric -> mean, sd
	}
	groups := map[string]*agg{}
	var keys []string
	metrics := map[string]func(run) float64{
		"throughput_rps":        func(r run) float64 { return r.Throughput },
		"mean_latency_ms":       func(r run) float64 { return r.MeanMS },
		"p50_latency_ms":        func(r run) float64 { return r.P50MS },
		"p95_latency_ms":        func(r run) float64 { return r.P95MS },
		"p99_latency_ms":        func(r run) float64 { return r.P99MS },
		"client_encrypt_us":     func(r run) float64 { return r.EncryptMeanUS },
		"api_cpu_ms_per_req":    func(r run) float64 { return r.APICPUMS / float64(r.Requests) },
		"client_cpu_ms_per_req": func(r run) float64 { return r.ClientCPUMS / float64(r.Requests) },
		"api_peak_rss_mb":       func(r run) float64 { return float64(r.APIPeakRSSKB) / 1024 },
		"bytes_per_req":         func(r run) float64 { return r.BytesPerReq },
	}
	for _, r := range runs {
		k := fmt.Sprintf("%s|%d", r.Mode, r.Conc)
		if groups[k] == nil {
			groups[k] = &agg{Mode: r.Mode, Conc: r.Conc, M: map[string][2]float64{}}
			keys = append(keys, k)
		}
		groups[k].N++
	}
	for k, g := range groups {
		for name, fn := range metrics {
			var v []float64
			for _, r := range runs {
				if fmt.Sprintf("%s|%d", r.Mode, r.Conc) == k {
					v = append(v, fn(r))
				}
			}
			var s float64
			for _, x := range v {
				s += x
			}
			m := s / float64(len(v))
			var ss float64
			for _, x := range v {
				ss += (x - m) * (x - m)
			}
			sd := 0.0
			if len(v) > 1 {
				sd = math.Sqrt(ss / float64(len(v)-1))
			}
			g.M[name] = [2]float64{m, sd}
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := groups[keys[i]], groups[keys[j]]
		if a.Conc != b.Conc {
			return a.Conc < b.Conc
		}
		return a.Mode < b.Mode
	})

	var sb strings.Builder
	fmt.Fprintf(&sb, "# Hasil benchmark end-to-end (baseline vs secure)\n\nGo %s · %s/%s · %d CPU tersedia · %d request terukur (secure; baseline memakai lebih banyak) + %d warm-up per run · API di-pin ke core %q · HTTPS/TLS aktif pada kedua mode\n\n",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), n, warm, apiCPU)
	sb.WriteString("Nilai: rata-rata ± simpangan baku antar-trial.\n\n")
	order := []string{"throughput_rps", "mean_latency_ms", "p50_latency_ms", "p95_latency_ms", "p99_latency_ms", "client_encrypt_us", "api_cpu_ms_per_req", "client_cpu_ms_per_req", "api_peak_rss_mb", "bytes_per_req"}
	sb.WriteString("| Mode | Konkurensi | Trial | " + strings.Join(order, " | ") + " |\n|---|---|---|" + strings.Repeat("---|", len(order)) + "\n")
	for _, k := range keys {
		g := groups[k]
		cells := make([]string, 0, len(order))
		for _, name := range order {
			cells = append(cells, fmt.Sprintf("%.3f ± %.3f", g.M[name][0], g.M[name][1]))
		}
		fmt.Fprintf(&sb, "| %s | %d | %d | %s |\n", g.Mode, g.Conc, g.N, strings.Join(cells, " | "))
	}
	if err := os.WriteFile(filepath.Join(dir, "e2e_summary.md"), []byte(sb.String()), 0o644); err != nil {
		log.Fatal(err)
	}
	type outRow struct {
		Mode string                `json:"mode"`
		Conc int                   `json:"concurrency"`
		N    int                   `json:"trials"`
		M    map[string][2]float64 `json:"metrics_mean_sd"`
	}
	var rows []outRow
	for _, k := range keys {
		g := groups[k]
		rows = append(rows, outRow{g.Mode, g.Conc, g.N, g.M})
	}
	jb, _ := json.MarshalIndent(map[string]any{"rows": rows, "requests": n, "warmup": warm, "api_cpu_pin": apiCPU, "go": runtime.Version()}, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "e2e_summary.json"), jb, 0o644)
	fmt.Printf("wrote %s/e2e_raw.csv, e2e_summary.md, e2e_summary.json\n", dir)
}
