# Benchmark primitif kriptografi

Go go1.27.4-X:nodwarf5 · linux/amd64 · 16 CPU · 5 pengulangan per operasi · benchtime per pengulangan lihat flag

Ukuran payload contoh: 118 byte; ukuran envelope JSON: 1406 byte (overhead 11.9×)

| Operasi | Parameter | Payload (B) | Rata-rata | SD | Throughput |
|---|---|---|---|---|---|
| sha256 | - | 256 | 169 ns | 1 ns | 1511 MB/s |
| sha256 | - | 1024 | 495 ns | 4 ns | 2067 MB/s |
| sha256 | - | 16384 | 7.08 µs | 131 ns | 2316 MB/s |
| aes_gcm_seal | AES-128-GCM | 256 | 161 ns | 1 ns | 1594 MB/s |
| aes_gcm_open | AES-128-GCM | 256 | 153 ns | 3 ns | 1673 MB/s |
| aes_gcm_seal | AES-256-GCM | 256 | 169 ns | 4 ns | 1518 MB/s |
| aes_gcm_open | AES-256-GCM | 256 | 158 ns | 3 ns | 1624 MB/s |
| aes_cbc_hmac_seal | AES-256-CBC+HMAC | 256 | 966 ns | 15 ns | 265 MB/s |
| aes_cbc_hmac_open | AES-256-CBC+HMAC | 256 | 853 ns | 10 ns | 300 MB/s |
| aes_gcm_seal | AES-128-GCM | 1024 | 385 ns | 3 ns | 2657 MB/s |
| aes_gcm_open | AES-128-GCM | 1024 | 377 ns | 3 ns | 2718 MB/s |
| aes_gcm_seal | AES-256-GCM | 1024 | 405 ns | 2 ns | 2528 MB/s |
| aes_gcm_open | AES-256-GCM | 1024 | 395 ns | 6 ns | 2590 MB/s |
| aes_cbc_hmac_seal | AES-256-CBC+HMAC | 1024 | 2.13 µs | 23 ns | 481 MB/s |
| aes_cbc_hmac_open | AES-256-CBC+HMAC | 1024 | 1.60 µs | 8 ns | 641 MB/s |
| aes_gcm_seal | AES-128-GCM | 16384 | 4.26 µs | 85 ns | 3847 MB/s |
| aes_gcm_open | AES-128-GCM | 16384 | 4.39 µs | 70 ns | 3736 MB/s |
| aes_gcm_seal | AES-256-GCM | 16384 | 4.65 µs | 66 ns | 3520 MB/s |
| aes_gcm_open | AES-256-GCM | 16384 | 4.69 µs | 40 ns | 3493 MB/s |
| aes_cbc_hmac_seal | AES-256-CBC+HMAC | 16384 | 24.59 µs | 271 ns | 666 MB/s |
| aes_cbc_hmac_open | AES-256-CBC+HMAC | 16384 | 16.36 µs | 165 ns | 1002 MB/s |
| rsa_keygen | RSA-2048 | 0 | 47.26 ms | 6.71 ms | - |
| rsa_oaep_wrap | RSA-2048 | 32 | 24.23 µs | 343 ns | - |
| rsa_oaep_unwrap | RSA-2048 | 32 | 748.90 µs | 3.69 µs | - |
| rsa_pss_sign | RSA-2048 | 256 | 772.00 µs | 3.96 µs | - |
| rsa_pss_verify | RSA-2048 | 256 | 24.27 µs | 244 ns | - |
| rsa_keygen | RSA-3072 | 0 | 191.70 ms | 39.02 ms | - |
| rsa_oaep_wrap | RSA-3072 | 32 | 108.42 µs | 946 ns | - |
| rsa_oaep_unwrap | RSA-3072 | 32 | 2.10 ms | 10.86 µs | - |
| rsa_pss_sign | RSA-3072 | 256 | 2.18 ms | 18.58 µs | - |
| rsa_pss_verify | RSA-3072 | 256 | 107.79 µs | 2.85 µs | - |
| ecdh_keygen | X25519 | 0 | 35.04 µs | 138 ns | - |
| ecdh_agree | X25519 | 0 | 35.04 µs | 528 ns | - |
| ecdh_hkdf_sender_total | X25519 | 32 | 71.49 µs | 373 ns | - |
| ecdh_keygen | P-256 | 0 | 10.17 µs | 106 ns | - |
| ecdh_agree | P-256 | 0 | 40.55 µs | 533 ns | - |
| ecdh_hkdf_sender_total | P-256 | 32 | 52.24 µs | 371 ns | - |
| sig_keygen | Ed25519 | 0 | 14.08 µs | 101 ns | - |
| sig_sign | Ed25519 | 256 | 17.33 µs | 60 ns | - |
| sig_verify | Ed25519 | 256 | 39.52 µs | 140 ns | - |
| sig_sign | ECDSA-P256 | 256 | 24.74 µs | 246 ns | - |
| sig_verify | ECDSA-P256 | 256 | 54.11 µs | 603 ns | - |
| envelope_seal | RSA-3072 | 118 | 2.31 ms | 6.97 µs | - |
| envelope_open | RSA-3072 | 118 | 2.21 ms | 19.46 µs | - |
