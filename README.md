# Sentinel

Sentinel adalah prototipe monitoring service dengan komunikasi aman antara **Worker** dan **API**. Worker melakukan health check terhadap target, lalu mengirimkan hasilnya ke API.

Pada mode secure, payload dibungkus menggunakan:

- RSA-OAEP untuk membungkus session key;
- AES-256-GCM untuk enkripsi dan autentikasi payload;
- RSA-PSS untuk tanda tangan Worker;
- replay guard berbasis timestamp, sequence, dan message ID;
- HTTPS/TLS untuk koneksi jaringan;
- public-key pinning untuk mencegah key substitution.

Endpoint plain hanya tersedia untuk baseline perbandingan benchmark dan tidak boleh digunakan sebagai konfigurasi produksi.

## Prasyarat

- Go 1.24 atau yang lebih baru
- Linux dengan `/proc` jika ingin menjalankan benchmark end-to-end
- `taskset` jika ingin melakukan pinning CPU pada benchmark

Semua perintah berikut dijalankan dari direktori root repository.

## Menjalankan test

```bash
go test ./...
```

Untuk pemeriksaan tambahan:

```bash
gofmt -d .
go vet ./...
```

## Menyiapkan key dan sertifikat

Buat key API, key Worker, daftar trusted Worker, serta sertifikat TLS self-signed:

```bash
go run ./cmd/keygen -dir keys
```

Perintah tersebut membuat file berikut:

```text
keys/
├── api/api-key-01.key.pem
├── api/api-key-01.pub.pem
├── api/api-key-01.fingerprint
├── workers/worker-01.key.pem
├── workers/worker-02.key.pem
├── trusted-workers/worker-01.pub.pem
├── trusted-workers/worker-02.pub.pem
└── tls/{cert,key}.pem
```

Key dan sertifikat di dalam `keys/` tidak boleh di-commit ke repository.

## Demo alur kriptografi

Demo ini tidak memerlukan API yang sedang berjalan. Demo membuat key sementara, mengenkripsi satu pesan, membuka envelope, lalu memperagakan penolakan terhadap tampering dan replay:

```bash
go run ./cmd/demo
```

## Menjalankan API dan Worker

Jalankan API pada terminal pertama:

```bash
go run ./cmd/api -keys keys -addr 127.0.0.1:8443 -tls=true
```

API memakai HTTPS dengan sertifikat self-signed dari `keys/tls/`. Jika `SENTINEL_ADMIN_TOKEN` tidak diatur, endpoint read terbuka karena ini ditujukan untuk lab.

Jalankan Worker pada terminal kedua:

```bash
go run ./cmd/worker \
  -api https://127.0.0.1:8443 \
  -keys keys \
  -key-id api-key-01 \
  -id worker-01 \
  -pin-from-keys \
  -targets example=https://example.com \
  -once
```

Tanpa `-once`, Worker akan melakukan pengecekan berulang setiap 30 detik. Interval dapat diubah, misalnya:

```bash
go run ./cmd/worker -keys keys -pin-from-keys -interval 10s
```

`-pin-from-keys` membuat Worker menggunakan public key API dari file lokal dan memverifikasi key tersebut. Untuk demonstrasi trust-on-first-fetch yang tidak aman, opsi ini dapat dihilangkan, tetapi konfigurasi tersebut tidak dianjurkan.

## Memeriksa API

Health check tidak membutuhkan token:

```bash
curl --cacert keys/tls/cert.pem https://127.0.0.1:8443/healthz
```

Melihat hasil monitoring:

```bash
curl --cacert keys/tls/cert.pem https://127.0.0.1:8443/v1/results
```

Melihat event keamanan:

```bash
curl --cacert keys/tls/cert.pem https://127.0.0.1:8443/v1/security/events
```

Melihat statistik:

```bash
curl --cacert keys/tls/cert.pem https://127.0.0.1:8443/v1/stats
```

Jika API dijalankan dengan `SENTINEL_ADMIN_TOKEN`, tambahkan header berikut ke endpoint read:

```bash
export SENTINEL_ADMIN_TOKEN='token-lokal-untuk-lab'
go run ./cmd/api -keys keys -tls=true
curl --cacert keys/tls/cert.pem \
  -H "Authorization: Bearer $SENTINEL_ADMIN_TOKEN" \
  https://127.0.0.1:8443/v1/results
```

## Menjalankan attack simulation

Attack simulation membuat key sementara dan menguji skenario seperti tampering, signature invalid, replay, stale timestamp, dan sender yang tidak dipercaya:

```bash
go run ./cmd/attacklab -out results
```

Output ditulis ke:

```text
results/attack_results.json
results/attack_results.md
```

Program keluar dengan status gagal jika ada skenario yang menyimpang dari hasil yang diharapkan.

## Menjalankan benchmark kriptografi

Benchmark ini mengukur primitive kriptografi dan operasi full envelope tanpa jaringan:

```bash
go run ./cmd/cryptobench -out results
```

Durasi default setiap pengulangan adalah 300 ms dan dilakukan 5 pengulangan per operasi. Contoh konfigurasi yang lebih ringan:

```bash
go run ./cmd/cryptobench -out results -repeats 3 -benchtime 100ms
```

Output:

```text
results/crypto_bench_raw.csv
results/crypto_bench_summary.md
results/crypto_bench_summary.json
```

## Menjalankan benchmark end-to-end

Benchmark end-to-end menjalankan API sebagai proses terpisah, lalu membandingkan mode `plain` dan `secure` melalui HTTPS. Build binary terlebih dahulu:

```bash
go build -o bin/api ./cmd/api
go build -o bin/bench ./cmd/bench
```

Lalu jalankan benchmark:

```bash
./bin/bench \
  -api-bin bin/api \
  -keys keys \
  -trials 8 \
  -requests 1000 \
  -requests-plain 20000 \
  -warmup 100 \
  -conc 1,8 \
  -api-cpu 0 \
  -out results
```

Untuk uji cepat, gunakan jumlah request dan trial yang lebih kecil:

```bash
./bin/bench \
  -api-bin bin/api \
  -keys keys \
  -trials 2 \
  -requests 100 \
  -requests-plain 500 \
  -warmup 10 \
  -conc 1 \
  -out results
```

Output benchmark:

```text
results/e2e_raw.csv
results/e2e_summary.md
results/e2e_summary.json
```

## Build semua binary

Jika ingin menjalankan binary tanpa `go run`:

```bash
for cmd in api attacklab bench cryptobench demo keygen worker; do
  go build -o "bin/$cmd" "./cmd/$cmd"
done
```

Binary yang tersedia:

| Binary | Fungsi |
|---|---|
| `bin/api` | Menjalankan REST API Sentinel |
| `bin/worker` | Melakukan health check dan mengirim hasil |
| `bin/keygen` | Membuat key, trusted-worker registry, dan TLS |
| `bin/demo` | Demo envelope, tampering, dan replay |
| `bin/attacklab` | Menjalankan simulasi serangan |
| `bin/cryptobench` | Benchmark primitive kriptografi |
| `bin/bench` | Benchmark komunikasi end-to-end |

## Catatan keamanan

Konfigurasi repository ini ditujukan untuk eksperimen dan penelitian lokal, bukan deployment produksi langsung.

- Sertifikat TLS yang dibuat `keygen` adalah self-signed.
- Endpoint plain hanya untuk baseline benchmark.
- Jangan menggunakan `-allow-plain` pada deployment nyata.
- Jangan menghilangkan public-key pinning pada deployment nyata.
- Gunakan `SENTINEL_ADMIN_TOKEN` untuk endpoint read.
- Simpan file private key dengan aman dan jangan commit ke Git.
- Data API saat ini disimpan di memory dan akan hilang ketika proses berhenti.

## Struktur proyek

```text
cmd/          entry point untuk API, Worker, keygen, demo, dan benchmark
internal/     implementasi crypto, API, Worker, keystore, security, dan storage
keys/         key dan sertifikat lokal, diabaikan oleh Git
results/      hasil attack simulation dan benchmark
bin/          lokasi binary hasil build
```
