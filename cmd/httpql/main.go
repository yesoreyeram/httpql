// Command httpql starts the httpql engine HTTP server.
// Configuration is loaded from the file specified by HTTPQL_CONFIG env var
// (defaults to /etc/httpql/httpql-engine.yaml).
package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	httpqlpkg "github.com/yesoreyeram/httpql/pkg/httpql"
)

func main() {
	configPath := os.Getenv("HTTPQL_CONFIG")
	if configPath == "" {
		configPath = "/etc/httpql/httpql-engine.yaml"
	}
	hmacKey := os.Getenv("HTTPQL_CONFIG_HMAC_KEY")

	eng, err := httpqlpkg.New(httpqlpkg.Options{
		ConfigPath: configPath,
		HMACKeyHex: hmacKey,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "httpql: startup failed: %v\n", err)
		os.Exit(1)
	}

	// Admin API on a separate internal port.
	adminMux := http.NewServeMux()
	eng.RegisterAdminRoutes(adminMux)

	adminAddr := os.Getenv("HTTPQL_ADMIN_ADDR")
	if adminAddr == "" {
		adminAddr = ":9091"
	}

	go func() {
		fmt.Fprintf(os.Stdout, "httpql: admin API listening on %s\n", adminAddr)
		if err := http.ListenAndServe(adminAddr, adminMux); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "httpql: admin server error: %v\n", err)
		}
	}()

	// Wait for OS signal.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Fprintln(os.Stdout, "httpql: shutting down")
}
