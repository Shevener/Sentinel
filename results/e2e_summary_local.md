# Hasil benchmark end-to-end (baseline vs secure)

Go go1.27.4-X:nodwarf5 · linux/amd64 · 16 CPU tersedia · 1000 request terukur (secure; baseline memakai lebih banyak) + 100 warm-up per run · API di-pin ke core "0" · HTTPS/TLS aktif pada kedua mode

Nilai: rata-rata ± simpangan baku antar-trial.

| Mode | Konkurensi | Trial | throughput_rps | mean_latency_ms | p50_latency_ms | p95_latency_ms | p99_latency_ms | client_encrypt_us | api_cpu_ms_per_req | client_cpu_ms_per_req | api_peak_rss_mb | bytes_per_req |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | 1 | 8 | 27340.548 ± 338.358 | 0.037 ± 0.000 | 0.032 ± 0.000 | 0.054 ± 0.001 | 0.101 ± 0.003 | 0.000 ± 0.000 | 0.018 ± 0.000 | 0.029 ± 0.000 | 22.267 ± 0.321 | 127.875 ± 0.354 |
| secure | 1 | 8 | 162.872 ± 0.427 | 6.140 ± 0.016 | 6.066 ± 0.009 | 6.821 ± 0.041 | 7.205 ± 0.025 | 2989.600 ± 20.086 | 3.033 ± 0.014 | 3.174 ± 0.021 | 17.321 ± 1.042 | 1463.000 ± 0.000 |
| plain | 8 | 8 | 62365.830 ± 1129.141 | 0.126 ± 0.002 | 0.111 ± 0.001 | 0.281 ± 0.007 | 0.442 ± 0.017 | 0.000 ± 0.000 | 0.013 ± 0.000 | 0.034 ± 0.001 | 22.773 ± 0.644 | 128.000 ± 0.000 |
| secure | 8 | 8 | 400.134 ± 8.832 | 19.611 ± 0.443 | 19.333 ± 0.407 | 29.823 ± 1.231 | 33.895 ± 1.684 | 3146.729 ± 39.463 | 2.471 ± 0.057 | 3.260 ± 0.040 | 17.132 ± 0.891 | 1463.000 ± 0.000 |
