// Command httpql is the httpql HTTP query engine.
//
// Run a query:
//
//	httpql run 'GET https://api.example.com/users'
//	httpql run query.httpql
//	httpql run --namespace analytics-team --output text query.httpql
//
// Start the admin server (default when no sub-command is given):
//
//	httpql
//
// Configuration is loaded from the file pointed to by HTTPQL_CONFIG
// (defaults to /etc/httpql/httpql-engine.yaml).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/yesoreyeram/httpql/internal/query"
	httpqlpkg "github.com/yesoreyeram/httpql/pkg/httpql"
)

// version is set at build time via -ldflags "-X main.version=…".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		runServer()
		return
	}
	switch os.Args[1] {
	case "run":
		cmdRun(os.Args[2:])
	case "version", "--version", "-version":
		fmt.Printf("httpql %s\n", version)
	case "help", "--help", "-h":
		if len(os.Args) > 2 && os.Args[2] == "run" {
			printRunUsage()
		} else {
			printUsage()
		}
	default:
		fmt.Fprintf(os.Stderr, "httpql: unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// ─── run sub-command ──────────────────────────────────────────────────────────

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	ns := fs.String("namespace", "default", "Namespace to execute the query in")
	fs.StringVar(ns, "n", "default", "Namespace (shorthand for --namespace)")
	outFmt := fs.String("output", "json", "Output format: json or text")
	fs.StringVar(outFmt, "o", "json", "Output format (shorthand for --output)")
	cfgPath := fs.String("config", os.Getenv("HTTPQL_CONFIG"), "Path to httpql-engine.yaml")
	fs.Usage = printRunUsage
	_ = fs.Parse(args)

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "httpql run: a query string or file path is required")
		printRunUsage()
		os.Exit(1)
	}

	// Determine whether the argument is a file path or an inline query.
	queryText := remaining[0]
	if looksLikeFile(queryText) {
		data, err := os.ReadFile(queryText)
		if err != nil {
			fatalf("httpql run: cannot read file %q: %v", queryText, err)
		}
		queryText = string(data)
	}

	// Parse the query.
	pq, err := query.Parse(queryText)
	if err != nil {
		fatalf("httpql run: parse error: %v", err)
	}

	// Initialise engine (no config file → safe defaults).
	eng, err := httpqlpkg.New(httpqlpkg.Options{ConfigPath: *cfgPath})
	if err != nil {
		fatalf("httpql run: engine init: %v", err)
	}

	// Validate the query plan against the namespace policy.
	pq.Plan.Namespace = *ns
	result, err := eng.ValidatePlan(*ns, pq.Plan)
	if err != nil {
		fatalf("httpql run: plan rejected: %v", err)
	}
	if !result.Allowed {
		fatalf("httpql run: query rejected by namespace policy")
	}

	// Execute every request in the plan.
	type execResult struct {
		Name      string
		Status    int
		Headers   map[string]string
		Body      string
		FromCache bool
	}
	results := make([]execResult, len(pq.Requests))
	ctx := context.Background()
	for i, nr := range pq.Requests {
		req := nr.Request
		req.Namespace = *ns
		resp, err := eng.ExecuteRequest(ctx, *ns, req)
		if err != nil {
			label := nr.Name
			if label == "" {
				label = fmt.Sprintf("request[%d]", i)
			}
			fatalf("httpql run: %s: %v", label, err)
		}
		results[i] = execResult{
			Name:      nr.Name,
			Status:    resp.StatusCode,
			Headers:   resp.Headers,
			Body:      string(resp.Body),
			FromCache: resp.FromCache,
		}
	}

	// Print output.
	switch *outFmt {
	case "text":
		for _, r := range results {
			if r.Name != "" {
				fmt.Printf("=== %s ===\n", r.Name)
			}
			fmt.Printf("HTTP %d\n", r.Status)
			for k, v := range r.Headers {
				fmt.Printf("%s: %s\n", k, v)
			}
			fmt.Println()
			fmt.Println(r.Body)
		}
	default: // json
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if len(results) == 1 && results[0].Name == "" {
			// Single request → flat response object.
			_ = enc.Encode(map[string]any{
				"status":     results[0].Status,
				"headers":    results[0].Headers,
				"body":       tryParseJSON(results[0].Body),
				"from_cache": results[0].FromCache,
			})
		} else {
			// WITH block → map of name → response.
			out := make(map[string]any, len(results))
			for i, r := range results {
				key := r.Name
				if key == "" {
					key = fmt.Sprintf("request_%d", i)
				}
				out[key] = map[string]any{
					"status":     r.Status,
					"headers":    r.Headers,
					"body":       tryParseJSON(r.Body),
					"from_cache": r.FromCache,
				}
			}
			_ = enc.Encode(out)
		}
	}
}

// ─── server mode (default when no sub-command) ────────────────────────────────

func runServer() {
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

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Fprintln(os.Stdout, "httpql: shutting down")
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// looksLikeFile returns true when s is not an inline query (i.e. does not
// start with a recognised HTTP method or the WITH keyword).
func looksLikeFile(s string) bool {
	upper := strings.ToUpper(strings.TrimSpace(s))
	for _, prefix := range []string{
		"GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ", "WITH",
	} {
		if strings.HasPrefix(upper, prefix) {
			return false
		}
	}
	_, err := os.Stat(s)
	return err == nil
}

// tryParseJSON attempts to unmarshal s into a generic JSON value.
// If s is valid JSON, the structured value is returned; otherwise s itself.
func tryParseJSON(s string) any {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err == nil {
		return v
	}
	return s
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// ─── usage strings ────────────────────────────────────────────────────────────

func printUsage() {
	fmt.Print(`Usage: httpql <command> [flags] [arguments]

Commands:
  run        Execute an httpql query and print the response to stdout
  version    Print the version string
  help       Show help for a command

When no command is given, httpql starts the admin server.

Examples:
  httpql run 'GET https://api.example.com/users'
  httpql run --namespace analytics-team query.httpql
  httpql run --output text 'GET https://httpbin.org/get'
  httpql                      # start admin server on :9091

Run 'httpql help run' for details on the run command.
`)
}

func printRunUsage() {
	fmt.Print(`Usage: httpql run [flags] <query|file>

Execute an httpql query.  The argument may be an inline query string or a
path to a .httpql file.

Flags:
  -n, --namespace string   Namespace to execute in (default "default")
  -o, --output   string    Output format: json or text  (default "json")
      --config   string    Path to httpql-engine.yaml
                           (also read from HTTPQL_CONFIG env var)

Examples:
  # Simple GET, JSON output
  httpql run 'GET https://api.example.com/users'

  # POST with a JSON body
  httpql run 'POST https://api.example.com/items BODY JSON {"name":"widget"}'

  # Read query from a file, plain-text output
  httpql run --output text query.httpql

  # Run in a specific namespace
  httpql run --namespace analytics-team query.httpql

Query syntax quick reference:
  METHOD URL
  [HEADERS {"Key": "Value"}]
  [BODY JSON {...} | FORM key=val&... | TEXT ... | GRAPHQL {...}]
  [CONCURRENCY N]  [QUERY_TIMEOUT N]  [REQUEST_CACHE N]  [CACHE N]
  [RETRY N]  [REDIRECTS FOLLOW MAX N]
  [STOP_WHEN TOTAL_ITEMS >= N]  [STOP_WHEN PAGE_COUNT >= N]

  WITH
    name1 AS (METHOD URL [HEADERS ...] [BODY ...]),
    name2 AS (METHOD URL [HEADERS ...] [BODY ...])
  [hints...]
`)
}
