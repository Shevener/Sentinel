# Hasil benchmark end-to-end (baseline vs secure)

Go go1.27.4-X:nodwarf5 · linux/amd64 · 16 CPU tersedia · 1000 request terukur (secure; baseline memakai lebih banyak) + 100 warm-up per run · API di-pin ke core "0" · HTTPS/TLS aktif pada kedua mode

Nilai: rata-rata ± simpangan baku antar-trial.

| Mode | Konkurensi | Trial | throughput_rps | mean_latency_ms | p50_latency_ms | p95_latency_ms | p99_latency_ms | client_encrypt_us | api_cpu_ms_per_req | client_cpu_ms_per_req | api_peak_rss_mb | bytes_per_req |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | 1 | 8 | 29722.577 ± 297.607 | 0.034 ± 0.000 | 0.029 ± 0.000 | 0.050 ± 0.001 | 0.092 ± 0.003 | 0.000 ± 0.000 | 0.016 ± 0.000 | 0.027 ± 0.000 | 22.656 ± 1.106 | 128.000 ± 0.000 |
| secure | 1 | 8 | 166.061 ± 0.503 | 6.022 ± 0.018 | 6.001 ± 0.001 | 6.285 ± 0.194 | 7.232 ± 0.296 | 2947.444 ± 29.986 | 2.956 ± 0.024 | 3.132 ± 0.031 | 16.877 ± 0.704 | 1463.000 ± 0.000 |
| plain | 8 | 8 | 63617.104 ± 2523.838 | 0.124 ± 0.005 | 0.107 ± 0.005 | 0.283 ± 0.008 | 0.448 ± 0.021 | 0.000 ± 0.000 | 0.013 ± 0.001 | 0.033 ± 0.001 | 23.145 ± 0.888 | 128.000 ± 0.000 |
| secure | 8 | 8 | 395.921 ± 18.934 | 19.868 ± 0.954 | 19.965 ± 0.981 | 30.083 ± 1.332 | 33.748 ± 1.692 | 3114.759 ± 71.503 | 2.511 ± 0.117 | 3.227 ± 0.074 | 18.103 ± 0.932 | 1463.000 ± 0.000 |
