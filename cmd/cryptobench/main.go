// cryptobench measures cryptographic primitives in isolation (no network) and
// writes raw samples plus a summary to results/.
//
// Only the Go standard library is used (no third-party dependencies).
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"sentinel/internal/crypto"
)

type sample struct {
	Op      string
	Param   string
	Payload int
	Repeat  int
	NsPerOp float64
}

var (
	samples []sample
	repeats int
)

func bench(op, param string, payload int, fn func(b *testing.B)) {
	for r := 1; r <= repeats; r++ {
		res := testing.Benchmark(fn)
		samples = append(samples, sample{op, param, payload, r, float64(res.NsPerOp())})
	}
	fmt.Printf("  %-28s %-12s %6dB  done\n", op, param, payload)
}

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}

func randBytes(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }

func main() {
	out := flag.String("out", "results", "output directory")
	flag.IntVar(&repeats, "repeats", 5, "repeats per operation")
	benchtime := flag.String("benchtime", "300ms", "per-repeat benchmark time")
	flag.Parse()
	testing.Init()
	_ = flag.Set("test.benchtime", *benchtime)

	sizes := []int{256, 1024, 16384}

	fmt.Println("hash")
	for _, n := range sizes {
		data := randBytes(n)
		bench("sha256", "-", n, func(b *testing.B) {
			b.SetBytes(int64(n))
			for i := 0; i < b.N; i++ {
				sha256.Sum256(data)
			}
		})
	}

	fmt.Println("symmetric")
	for _, n := range sizes {
		pt := randBytes(n)
		aad := randBytes(64)
		for _, ks := range []int{16, 32} {
			key := randBytes(ks)
			block := must(aes.NewCipher(key))
			gcm := must(cipher.NewGCM(block))
			nonce := randBytes(gcm.NonceSize())
			ct := gcm.Seal(nil, nonce, pt, aad)
			p := fmt.Sprintf("AES-%d-GCM", ks*8)
			bench("aes_gcm_seal", p, n, func(b *testing.B) {
				b.SetBytes(int64(n))
				for i := 0; i < b.N; i++ {
					gcm.Seal(nil, nonce, pt, aad)
				}
			})
			bench("aes_gcm_open", p, n, func(b *testing.B) {
				b.SetBytes(int64(n))
				for i := 0; i < b.N; i++ {
					if _, err := gcm.Open(nil, nonce, ct, aad); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
		// AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC) as a non-AEAD-mode comparison
		ek, mk := randBytes(32), randBytes(32)
		blk := must(aes.NewCipher(ek))
		iv := randBytes(16)
		padded := n + (16 - n%16)
		ctb := make([]byte, padded)
		ptp := append(append([]byte{}, pt...), make([]byte, padded-n)...)
		bench("aes_cbc_hmac_seal", "AES-256-CBC+HMAC", n, func(b *testing.B) {
			b.SetBytes(int64(n))
			for i := 0; i < b.N; i++ {
				cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ctb, ptp)
				m := hmac.New(sha256.New, mk)
				m.Write(iv)
				m.Write(ctb)
				m.Sum(nil)
			}
		})
		tag := func() []byte { m := hmac.New(sha256.New, mk); m.Write(iv); m.Write(ctb); return m.Sum(nil) }()
		dst := make([]byte, padded)
		bench("aes_cbc_hmac_open", "AES-256-CBC+HMAC", n, func(b *testing.B) {
			b.SetBytes(int64(n))
			for i := 0; i < b.N; i++ {
				m := hmac.New(sha256.New, mk)
				m.Write(iv)
				m.Write(ctb)
				if !hmac.Equal(m.Sum(nil), tag) {
					b.Fatal("mac")
				}
				cipher.NewCBCDecrypter(blk, iv).CryptBlocks(dst, ctb)
			}
		})
	}

	fmt.Println("rsa")
	rsaKeys := map[int]*rsa.PrivateKey{}
	for _, bits := range []int{2048, 3072} {
		bits := bits
		p := fmt.Sprintf("RSA-%d", bits)
		bench("rsa_keygen", p, 0, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := rsa.GenerateKey(rand.Reader, bits); err != nil {
					b.Fatal(err)
				}
			}
		})
		k := must(rsa.GenerateKey(rand.Reader, bits))
		rsaKeys[bits] = k
		sk := randBytes(crypto.SessionKeySize)
		wrapped := must(crypto.WrapSessionKey(&k.PublicKey, "api-key-01", sk))
		bench("rsa_oaep_wrap", p, 32, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := crypto.WrapSessionKey(&k.PublicKey, "api-key-01", sk); err != nil {
					b.Fatal(err)
				}
			}
		})
		bench("rsa_oaep_unwrap", p, 32, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := crypto.UnwrapSessionKey(k, "api-key-01", wrapped); err != nil {
					b.Fatal(err)
				}
			}
		})
		msg := randBytes(256)
		sig := must(crypto.Sign(k, msg))
		bench("rsa_pss_sign", p, 256, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := crypto.Sign(k, msg); err != nil {
					b.Fatal(err)
				}
			}
		})
		bench("rsa_pss_verify", p, 256, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if err := crypto.Verify(&k.PublicKey, msg, sig); err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	fmt.Println("elliptic-curve key establishment (comparison only)")
	for _, c := range []struct {
		name  string
		curve ecdh.Curve
	}{{"X25519", ecdh.X25519()}, {"P-256", ecdh.P256()}} {
		c := c
		bench("ecdh_keygen", c.name, 0, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := c.curve.GenerateKey(rand.Reader); err != nil {
					b.Fatal(err)
				}
			}
		})
		a := must(c.curve.GenerateKey(rand.Reader))
		peer := must(c.curve.GenerateKey(rand.Reader))
		bench("ecdh_agree", c.name, 0, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := a.ECDH(peer.PublicKey()); err != nil {
					b.Fatal(err)
				}
			}
		})
		// Sender-side cost of one fresh key establishment: ephemeral keygen + ECDH + HKDF
		bench("ecdh_hkdf_sender_total", c.name, 32, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				e, err := c.curve.GenerateKey(rand.Reader)
				if err != nil {
					b.Fatal(err)
				}
				ss, err := e.ECDH(peer.PublicKey())
				if err != nil {
					b.Fatal(err)
				}
				if _, err := hkdf.Key(sha256.New, ss, nil, "sentinel/v1", 32); err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	fmt.Println("signature alternatives (comparison only)")
	{
		msg := randBytes(256)
		digest := sha256.Sum256(msg)
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		bench("sig_keygen", "Ed25519", 0, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, _, err := ed25519.GenerateKey(rand.Reader); err != nil {
					b.Fatal(err)
				}
			}
		})
		edsig := ed25519.Sign(priv, msg)
		bench("sig_sign", "Ed25519", 256, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ed25519.Sign(priv, msg)
			}
		})
		bench("sig_verify", "Ed25519", 256, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if !ed25519.Verify(pub, msg, edsig) {
					b.Fatal("verify")
				}
			}
		})
		ek := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
		esig := must(ecdsa.SignASN1(rand.Reader, ek, digest[:]))
		bench("sig_sign", "ECDSA-P256", 256, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := ecdsa.SignASN1(rand.Reader, ek, digest[:]); err != nil {
					b.Fatal(err)
				}
			}
		})
		bench("sig_verify", "ECDSA-P256", 256, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if !ecdsa.VerifyASN1(&ek.PublicKey, digest[:], esig) {
					b.Fatal("verify")
				}
			}
		})
	}

	fmt.Println("full envelope (RSA-3072 + RSA-PSS + AES-256-GCM)")
	api, w := rsaKeys[3072], must(rsa.GenerateKey(rand.Reader, 3072))
	payload := []byte(`{"service":"payment-api","status":"down","status_code":503,"response_time_ms":842,"checked_at":"2026-11-02T15:00:00Z"}`)
	sp := crypto.SealParams{KeyID: "api-key-01", WorkerID: "worker-01", MessageID: "m1", Sequence: 1, Timestamp: time.Now()}
	env := must(crypto.Seal(payload, &api.PublicKey, w, sp))
	bench("envelope_seal", "RSA-3072", len(payload), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := crypto.Seal(payload, &api.PublicKey, w, sp); err != nil {
				b.Fatal(err)
			}
		}
	})
	bench("envelope_open", "RSA-3072", len(payload), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := crypto.Open(env, api, &w.PublicKey); err != nil {
				b.Fatal(err)
			}
		}
	})
	encBytes, _ := json.Marshal(env)

	write(*out, encBytes, len(payload))
}

type stat struct {
	Op, Param string
	Payload   int
	Mean, SD  float64
	N         int
}

func summarize() []stat {
	type key struct {
		op, p string
		n     int
	}
	g := map[key][]float64{}
	var order []key
	for _, s := range samples {
		k := key{s.Op, s.Param, s.Payload}
		if _, ok := g[k]; !ok {
			order = append(order, k)
		}
		g[k] = append(g[k], s.NsPerOp)
	}
	var out []stat
	for _, k := range order {
		v := g[k]
		var sum float64
		for _, x := range v {
			sum += x
		}
		m := sum / float64(len(v))
		var ss float64
		for _, x := range v {
			ss += (x - m) * (x - m)
		}
		sd := 0.0
		if len(v) > 1 {
			sd = math.Sqrt(ss / float64(len(v)-1))
		}
		out = append(out, stat{k.op, k.p, k.n, m, sd, len(v)})
	}
	return out
}

func human(ns float64) string {
	switch {
	case ns >= 1e6:
		return fmt.Sprintf("%.2f ms", ns/1e6)
	case ns >= 1e3:
		return fmt.Sprintf("%.2f µs", ns/1e3)
	default:
		return fmt.Sprintf("%.0f ns", ns)
	}
}

func write(dir string, envelopeBytes []byte, payloadBytes int) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "crypto_bench_raw.csv"))
	if err != nil {
		log.Fatal(err)
	}
	cw := csv.NewWriter(f)
	_ = cw.Write([]string{"operation", "param", "payload_bytes", "repeat", "ns_per_op"})
	for _, s := range samples {
		_ = cw.Write([]string{s.Op, s.Param, strconv.Itoa(s.Payload), strconv.Itoa(s.Repeat), strconv.FormatFloat(s.NsPerOp, 'f', 0, 64)})
	}
	cw.Flush()
	f.Close()

	st := summarize()
	sort.SliceStable(st, func(i, j int) bool { return false })
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Benchmark primitif kriptografi\n\nGo %s · %s/%s · %d CPU · %d pengulangan per operasi · benchtime per pengulangan lihat flag\n\n", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), repeats)
	fmt.Fprintf(&sb, "Ukuran payload contoh: %d byte; ukuran envelope JSON: %d byte (overhead %.1f×)\n\n", payloadBytes, len(envelopeBytes), float64(len(envelopeBytes))/float64(payloadBytes))
	sb.WriteString("| Operasi | Parameter | Payload (B) | Rata-rata | SD | Throughput |\n|---|---|---|---|---|---|\n")
	for _, s := range st {
		tp := "-"
		if s.Payload >= 256 && strings.HasPrefix(s.Op, "aes_") || s.Op == "sha256" {
			tp = fmt.Sprintf("%.0f MB/s", float64(s.Payload)/s.Mean*1e3)
		}
		fmt.Fprintf(&sb, "| %s | %s | %d | %s | %s | %s |\n", s.Op, s.Param, s.Payload, human(s.Mean), human(s.SD), tp)
	}
	if err := os.WriteFile(filepath.Join(dir, "crypto_bench_summary.md"), []byte(sb.String()), 0o644); err != nil {
		log.Fatal(err)
	}
	jb, _ := json.MarshalIndent(map[string]any{"stats": st, "envelope_bytes": len(envelopeBytes), "payload_bytes": payloadBytes,
		"go": runtime.Version(), "cpus": runtime.NumCPU(), "repeats": repeats}, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "crypto_bench_summary.json"), jb, 0o644)
	fmt.Printf("wrote %s/crypto_bench_*.{csv,md,json}\n", dir)
}
