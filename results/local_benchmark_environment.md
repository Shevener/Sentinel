# Benchmark Lokal

## Mesin

- CPU: AMD Ryzen 7 7840HS w/ Radeon 780M Graphics
- Cores: 8 physical cores / 16 logical CPUs
- RAM: 15625308 kB total
- OS/kernel: Linux omen 7.3.5-2-cachyos #1 SMP PREEMPT_DYNAMIC Fri, 20 Nov 2026 07:37:39 +0000 x86_64 GNU/Linux
- Go: `go version go1.27.4-X:nodwarf5 linux/amd64`
- Go target: `linux/amd64`
- CPU pinning benchmark: API dipin ke logical CPU `0` menggunakan `taskset`

## Waktu eksekusi

- Benchmark dijalankan ulang: `2026-11-23T04:04:47Z`

## Perintah yang dijalankan

```sh
go test ./...
for p in api attacklab bench cryptobench demo keygen worker; do go build -o bin/$p ./cmd/$p; done
./bin/keygen -dir keys -workers worker-01
./bin/attacklab -out results/attack
./bin/bench -api-bin ./bin/api -keys keys -out results/bench \
  -trials 8 -requests 1000 -requests-plain 20000 \
  -warmup 100 -conc 1,8 -api-cpu 0
./bin/cryptobench -out results/crypto -repeats 5 -benchtime 300ms
```

## Konfigurasi

- Secure mode: 8 trial per concurrency, 1.000 request terukur per trial.
- Baseline: 8 trial per concurrency, 20.000 request terukur per trial.
- Warm-up: 100 request per run.
- Concurrency: 1 dan 8.
- HTTPS/TLS aktif pada kedua mode.
- API dipin ke logical CPU 0; pembangkit beban tidak dipin.
- Attack lab: 73 test case, 73 sesuai ekspektasi pada run ini.

## Berkas hasil

- `attack_results.json`, `attack_results.md`
- `e2e_raw_local.csv`, `e2e_summary_local.json`, `e2e_summary_local.md`
- `crypto_bench_raw_local.csv`, `crypto_bench_summary_local.json`, `crypto_bench_summary_local.md`
