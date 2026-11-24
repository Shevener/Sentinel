# Hasil Attack Simulation (dijalankan otomatis)

Dijalankan: 2026-11-24T02:18:00Z · Go go1.27.4-X:nodwarf5 · linux/amd64 · 16 CPU · RSA-3072

## Ringkasan

| Grup | Jumlah test case | Sesuai ekspektasi |
|---|---|---|
| AT-01 | 2 | 2 |
| AT-02 | 19 | 19 |
| AT-03 | 12 | 12 |
| AT-04 | 4 | 4 |
| AT-05 | 32 | 32 |
| AT-06 | 3 | 3 |
| AT-07 | 1 | 1 |

## Detail

| ID | Skenario | Expected | Actual | Status |
|---|---|---|---|---|
| AT-01a | Eksposur plaintext (baseline) | Isi payload (nama service, status, status code, response time) terbaca penuh oleh penyadap. | Semua penanda [payment-api 503 842 "down"] ditemukan di body tersadap: true (send err=<nil>) | SESUAI |
| AT-01b | Eksposur plaintext (secure mode) | Isi payload tidak dapat ditemukan pada envelope yang tersadap. | Penanda plaintext ditemukan: false (send err=<nil>); ukuran envelope 1463 byte vs plaintext 128 byte | SESUAI |
| AT-02-00 | Kontrol: envelope asli | Diterima (HTTP 202) dan disimpan. | HTTP 202 | SESUAI |
| AT-02-01 | Tampering oleh penyerang tanpa kunci: ciphertext (byte pertama) | Ditolak; tidak ada data yang diproses atau disimpan. | HTTP 401, event=sender_authentication/signature_invalid; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-02 | Tampering oleh penyerang tanpa kunci: authentication tag (byte terakhir) | Ditolak; tidak ada data yang diproses atau disimpan. | HTTP 401, event=sender_authentication/signature_invalid; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-03 | Tampering oleh penyerang tanpa kunci: nonce | Ditolak; tidak ada data yang diproses atau disimpan. | HTTP 401, event=sender_authentication/signature_invalid; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-04 | Tampering oleh penyerang tanpa kunci: encrypted_key | Ditolak; tidak ada data yang diproses atau disimpan. | HTTP 401, event=sender_authentication/signature_invalid; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-05 | Tampering oleh penyerang tanpa kunci: signature | Ditolak; tidak ada data yang diproses atau disimpan. | HTTP 401, event=sender_authentication/signature_invalid; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-06 | Tampering oleh penyerang tanpa kunci: sequence (metadata AAD) | Ditolak; tidak ada data yang diproses atau disimpan. | HTTP 401, event=sender_authentication/signature_invalid; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-07 | Tampering oleh penyerang tanpa kunci: timestamp (metadata AAD) | Ditolak; tidak ada data yang diproses atau disimpan. | HTTP 401, event=sender_authentication/signature_invalid; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-08 | Tampering oleh penyerang tanpa kunci: message_id (metadata AAD) | Ditolak; tidak ada data yang diproses atau disimpan. | HTTP 401, event=sender_authentication/signature_invalid; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-09 | Tampering oleh penyerang tanpa kunci: worker_id (metadata AAD) | Ditolak; tidak ada data yang diproses atau disimpan. | HTTP 401, event=sender_authentication/signature_invalid; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-10 | Tampering oleh penyerang tanpa kunci: key_id (metadata AAD) | Ditolak; tidak ada data yang diproses atau disimpan. | HTTP 401, event=sender_authentication/signature_invalid; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-11 | Tampering oleh pemegang kunci tanda tangan: ciphertext | Ditolak oleh lapisan AES-GCM/RSA-OAEP dengan alasan gcm_authentication_failed; tidak ada data tersimpan. | HTTP 400, event=integrity_failure/gcm_authentication_failed; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-12 | Tampering oleh pemegang kunci tanda tangan: authentication tag | Ditolak oleh lapisan AES-GCM/RSA-OAEP dengan alasan gcm_authentication_failed; tidak ada data tersimpan. | HTTP 400, event=integrity_failure/gcm_authentication_failed; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-13 | Tampering oleh pemegang kunci tanda tangan: nonce | Ditolak oleh lapisan AES-GCM/RSA-OAEP dengan alasan gcm_authentication_failed; tidak ada data tersimpan. | HTTP 400, event=integrity_failure/gcm_authentication_failed; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-14 | Tampering oleh pemegang kunci tanda tangan: sequence (AAD) | Ditolak oleh lapisan AES-GCM/RSA-OAEP dengan alasan gcm_authentication_failed; tidak ada data tersimpan. | HTTP 400, event=integrity_failure/gcm_authentication_failed; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-15 | Tampering oleh pemegang kunci tanda tangan: timestamp (AAD) | Ditolak oleh lapisan AES-GCM/RSA-OAEP dengan alasan gcm_authentication_failed; tidak ada data tersimpan. | HTTP 400, event=integrity_failure/gcm_authentication_failed; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-16 | Tampering oleh pemegang kunci tanda tangan: message_id (AAD) | Ditolak oleh lapisan AES-GCM/RSA-OAEP dengan alasan gcm_authentication_failed; tidak ada data tersimpan. | HTTP 400, event=integrity_failure/gcm_authentication_failed; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-17 | Tampering oleh pemegang kunci tanda tangan: encrypted_key | Ditolak oleh lapisan AES-GCM/RSA-OAEP dengan alasan key_unwrap_failed; tidak ada data tersimpan. | HTTP 400, event=integrity_failure/key_unwrap_failed; stored sebelum/sesudah=1/1 | SESUAI |
| AT-02-18 | Tampering oleh pemegang kunci tanda tangan: key_id -> api-key-02 (label/AAD) | Ditolak oleh lapisan AES-GCM/RSA-OAEP dengan alasan key_unwrap_failed; tidak ada data tersimpan. | HTTP 400, event=integrity_failure/key_unwrap_failed; stored sebelum/sesudah=1/1 | SESUAI |
| AT-03-00 | Kontrol: pesan pertama | Diterima (HTTP 202). | HTTP 202 | SESUAI |
| AT-03-01 | Replay segera | Ditolak (HTTP 409); jumlah data tersimpan tidak bertambah. | HTTP 409, event=replay_rejected/duplicate_message_id; stored=1 | SESUAI |
| AT-03-02 | Replay setelah pesan lain diproses | Tetap ditolak (HTTP 409). | HTTP 409, event=replay_rejected/duplicate_message_id; stored sebelum/sesudah=6/6 | SESUAI |
| AT-03-03 | Sequence number ganda dengan message_id berbeda | Ditolak (HTTP 409, duplicate_sequence). | HTTP 409, event=replay_rejected/duplicate_sequence | SESUAI |
| AT-03-04 | message_id ganda dengan sequence baru | Ditolak (HTTP 409, duplicate_message_id). | HTTP 409, event=replay_rejected/duplicate_message_id | SESUAI |
| AT-03-05 | Sequence di bawah replay window | Ditolak (HTTP 409, sequence_too_old). | HTTP 409, event=replay_rejected/sequence_too_old | SESUAI |
| AT-03-06 | Timestamp kedaluwarsa | Ditolak (HTTP 409, stale_timestamp). | HTTP 409, event=replay_rejected/stale_timestamp | SESUAI |
| AT-03-07 | Timestamp di masa depan | Ditolak (HTTP 409, stale_timestamp). | HTTP 409, event=replay_rejected/stale_timestamp | SESUAI |
| AT-03-08 | Kontrol: pesan sah datang tidak berurutan | Diterima (tidak ada false positive). | HTTP 202 | SESUAI |
| AT-03-09 | Envelope palsu tidak boleh menghabiskan sequence | Envelope palsu ditolak dan pesan sah berikutnya tetap diterima (state replay hanya diubah setelah autentikasi). | palsu: HTTP 401, event=sender_authentication/signature_invalid; sah berikutnya: HTTP 202 | SESUAI |
| AT-03-10 | Replay konkuren (race) | Tepat 1 diterima (202); 49 lainnya ditolak (409). | distribusi status: map[202:1 409:49] | SESUAI |
| AT-03-11 | Kontrol: Worker restart | Diterima, karena sequence awal berbasis waktu (mikrodetik) tetap monoton. | HTTP 202 | SESUAI |
| AT-04-01 | Substitusi public key tanpa verifikasi | Penyerang dapat mendekripsi payload (kerahasiaan hilang): ini membuktikan RSA-OAEP saja tidak mencegah MITM. | plaintext terbaca penyerang: true; hasil kiriman ke API asli: api rejected message (HTTP 400) | SESUAI |
| AT-04-02 | Dampak substitusi terhadap API asli | API menolak (key_unwrap_failed); tidak ada data tersimpan. Penyerang membaca pesan tetapi tidak dapat meneruskannya sebagai pesan sah karena signature Worker mencakup encrypted_key. | stored=0; alasan penolakan API=key_unwrap_failed | SESUAI |
| AT-04-03 | Substitusi public key dengan pinning fingerprint | Worker menolak key (fingerprint tidak cocok) dan tidak mengirim pesan apa pun. | error Worker: API public key does not match pinned fingerprint; pesan secure yang terkirim ke penyerang: 0 | SESUAI |
| AT-04-04 | Kontrol: pinning tanpa serangan | Key diterima dan pesan diterima API (202). | error pembuatan client: <nil>; error kirim: <nil>; stored=1 | SESUAI |
| AT-05-01 | Envelope tidak valid: body kosong | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-02 | Envelope tidak valid: bukan JSON | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-03 | Envelope tidak valid: JSON null | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-04 | Envelope tidak valid: JSON array | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-05 | Envelope tidak valid: objek kosong {} | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-06 | Envelope tidak valid: data sisa setelah JSON | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-07 | Envelope tidak valid: field tidak dikenal | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-08 | Envelope tidak valid: versi 2 | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-09 | Envelope tidak valid: versi 0 | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-10 | Envelope tidak valid: tipe sequence salah (string) | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-11 | Envelope tidak valid: timestamp bukan RFC3339 | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-12 | Envelope tidak valid: nonce panjang 8 byte | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-13 | Envelope tidak valid: ciphertext 4 byte (< tag) | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-14 | Envelope tidak valid: key_id tidak dikenal | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/unknown_key_id; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-15 | Envelope tidak valid: key_id berisi karakter ilegal | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-16 | Envelope tidak valid: body 200 KB (melebihi batas) | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-17 | Envelope tidak valid: worker tidak terdaftar | Ditolak dengan HTTP 401 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 401, event=sender_authentication/unknown_worker; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-18 | Envelope tidak valid: field 'version' hilang | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-19 | Envelope tidak valid: field 'key_id' hilang | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-20 | Envelope tidak valid: field 'worker_id' hilang | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-21 | Envelope tidak valid: field 'encrypted_key' hilang | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-22 | Envelope tidak valid: field 'nonce' hilang | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-23 | Envelope tidak valid: field 'ciphertext' hilang | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-24 | Envelope tidak valid: field 'sequence' hilang | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-25 | Envelope tidak valid: field 'timestamp' hilang | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-26 | Envelope tidak valid: field 'message_id' hilang | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-27 | Envelope tidak valid: field 'signature' hilang | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-28 | Envelope tidak valid: base64 rusak pada 'encrypted_key' | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-29 | Envelope tidak valid: base64 rusak pada 'nonce' | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-30 | Envelope tidak valid: base64 rusak pada 'ciphertext' | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-31 | Envelope tidak valid: base64 rusak pada 'signature' | Ditolak dengan HTTP 400 tanpa crash dan tanpa menyimpan data; kejadian tercatat sebagai security event. | HTTP 400, event=invalid_envelope/malformed_envelope; stored sebelum/sesudah=0/0 | SESUAI |
| AT-05-99 | Kontrol: API tetap sehat setelah input tidak valid | Healthz OK dan envelope valid diterima. | healthz=true; HTTP 202 | SESUAI |
| AT-06-01 | Pemalsuan pengirim: menyamar sebagai worker-01 | Ditolak (HTTP 401, signature_invalid). Tanpa tanda tangan, enkripsi dengan public key saja tidak membuktikan identitas pengirim. | HTTP 401, event=sender_authentication/signature_invalid | SESUAI |
| AT-06-02 | Pemalsuan pengirim: identitas worker tidak terdaftar | Ditolak (HTTP 401, unknown_worker). | HTTP 401, event=sender_authentication/unknown_worker | SESUAI |
| AT-06-03 | Endpoint baseline tidak terbuka pada deployment secure | Ditolak (HTTP 404); tidak ada data tersimpan. | HTTP 404; stored=0 | SESUAI |
| AT-07-01 | Respons tidak membocorkan tahap kegagalan (anti-oracle) | Respons HTTP (status + body) identik untuk ketiganya, sedangkan security event internal mencatat alasan yang berbeda. | respons: [400 {"error":"rejected"}] [400 {"error":"rejected"}] [400 {"error":"rejected"}]; alasan internal: gcm_authentication_failed \| key_unwrap_failed \| malformed_envelope | SESUAI |
