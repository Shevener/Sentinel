// attacklab runs the attack simulations and writes the evidence files
// results/attack_results.json and results/attack_results.md.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"sentinel/internal/lab"
)

func main() {
	out := flag.String("out", "results", "output directory")
	flag.Parse()

	t0 := time.Now()
	keys, err := lab.GenKeys()
	if err != nil {
		log.Fatal(err)
	}
	res := lab.RunAll(keys)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}

	meta := map[string]any{
		"run_at": t0.UTC().Format(time.RFC3339), "duration_s": time.Since(t0).Seconds(),
		"go": runtime.Version(), "os_arch": runtime.GOOS + "/" + runtime.GOARCH, "cpus": runtime.NumCPU(),
		"rsa_bits": 3072,
	}
	b, _ := json.MarshalIndent(map[string]any{"meta": meta, "results": res}, "", "  ")
	if err := os.WriteFile(filepath.Join(*out, "attack_results.json"), b, 0o644); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*out, "attack_results.md"), []byte(markdown(meta, res)), 0o644); err != nil {
		log.Fatal(err)
	}

	failed := 0
	for _, r := range res {
		if !r.Pass {
			failed++
			fmt.Printf("DEVIATION %s %s\n  expected: %s\n  actual:   %s\n", r.ID, r.Scenario, r.Expected, r.Actual)
		}
	}
	fmt.Printf("%d test cases, %d as expected, %d deviations (%.1fs)\n", len(res), len(res)-failed, failed, time.Since(t0).Seconds())
	if failed > 0 {
		os.Exit(1)
	}
}

func esc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

func markdown(meta map[string]any, res []lab.Result) string {
	var sb strings.Builder
	sb.WriteString("# Hasil Attack Simulation (dijalankan otomatis)\n\n")
	fmt.Fprintf(&sb, "Dijalankan: %v · Go %v · %v · %v CPU · RSA-%v\n\n", meta["run_at"], meta["go"], meta["os_arch"], meta["cpus"], meta["rsa_bits"])

	groups := map[string][2]int{}
	var order []string
	for _, r := range res {
		g, ok := groups[r.Group]
		if !ok {
			order = append(order, r.Group)
		}
		g[0]++
		if r.Pass {
			g[1]++
		}
		groups[r.Group] = g
	}
	sort.Strings(order)
	sb.WriteString("## Ringkasan\n\n| Grup | Jumlah test case | Sesuai ekspektasi |\n|---|---|---|\n")
	for _, g := range order {
		fmt.Fprintf(&sb, "| %s | %d | %d |\n", g, groups[g][0], groups[g][1])
	}
	sb.WriteString("\n## Detail\n\n| ID | Skenario | Expected | Actual | Status |\n|---|---|---|---|---|\n")
	for _, r := range res {
		st := "SESUAI"
		if !r.Pass {
			st = "MENYIMPANG"
		}
		fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s |\n", r.ID, esc(r.Scenario), esc(r.Expected), esc(r.Actual), st)
	}
	return sb.String()
}
