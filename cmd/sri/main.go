// cmd/sri/main.go prints the Subresource Integrity (SRI) hash of a file in the
// format required by HTML integrity attributes: "sha384-<base64>".
//
// Usage: go run ./cmd/sri <file>
package main

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("usage: sri <file>")
	}

	f, err := os.Open(os.Args[1]) //nolint:gosec // G703: CLI tool; caller controls the path intentionally
	if err != nil {
		log.Fatalf("open: %v", err)
	}

	h := sha512.New384()
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		log.Fatalf("hash: %v", err)
	}
	f.Close()

	fmt.Printf("sha384-%s\n", base64.StdEncoding.EncodeToString(h.Sum(nil)))
}
