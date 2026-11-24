// keygen creates the lab key material: API RSA-OAEP key pair, worker
// RSA-PSS key pair(s), trusted-worker registry, and a self-signed TLS pair.
package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"sentinel/internal/crypto"
	"sentinel/internal/keystore"
	"sentinel/internal/tlsutil"
)

func main() {
	dir := flag.String("dir", "keys", "output directory")
	keyID := flag.String("key-id", "api-key-01", "API key id")
	workers := flag.String("workers", "worker-01,worker-02", "comma-separated worker ids")
	bits := flag.Int("bits", crypto.DefaultRSABits, "RSA modulus size")
	flag.Parse()

	api, err := crypto.GenerateRSAKey(*bits)
	must(err)
	priv, err := crypto.EncodePrivateKeyPEM(api)
	must(err)
	pub, err := crypto.EncodePublicKeyPEM(&api.PublicKey)
	must(err)
	must(keystore.WriteFile(filepath.Join(*dir, "api", *keyID+".key.pem"), priv))
	must(keystore.WriteFile(filepath.Join(*dir, "api", *keyID+".pub.pem"), pub))
	fp, err := crypto.Fingerprint(&api.PublicKey)
	must(err)
	fmt.Printf("API key %s (RSA-%d) fingerprint: %s\n", *keyID, *bits, fp)
	must(keystore.WriteFile(filepath.Join(*dir, "api", *keyID+".fingerprint"), []byte(fp+"\n")))

	for _, id := range strings.Split(*workers, ",") {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		k, err := crypto.GenerateRSAKey(*bits)
		must(err)
		kp, _ := crypto.EncodePrivateKeyPEM(k)
		kpub, _ := crypto.EncodePublicKeyPEM(&k.PublicKey)
		must(keystore.WriteFile(filepath.Join(*dir, "workers", id+".key.pem"), kp))
		must(keystore.WriteFile(filepath.Join(*dir, "trusted-workers", id+".pub.pem"), kpub))
		fmt.Printf("worker %s: signing key created and registered as trusted\n", id)
	}

	cert, key, err := tlsutil.GenerateSelfSigned()
	must(err)
	must(keystore.WriteFile(filepath.Join(*dir, "tls", "cert.pem"), cert))
	must(keystore.WriteFile(filepath.Join(*dir, "tls", "key.pem"), key))
	fmt.Println("TLS self-signed certificate written (lab only)")
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
