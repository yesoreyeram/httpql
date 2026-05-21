package secrets

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yesoreyeram/httpql/internal/config"
)

// vaultProvider implements [Provider] using the HashiCorp Vault HTTP API
// (KV Secrets Engine v2).  No third-party SDK is required.
//
// Key convention: "{secret-path}/{field}"
//
//   - Everything up to the last "/" is the secret path relative to the KV mount.
//   - The last segment is the field name within the secret's data map.
//
// Example: key "database/postgres/password" is resolved as:
//
//	GET {vault_address}/v1/{mount}/data/database/postgres
//	→ response.data.data["password"]
//
// Authentication uses a Vault token read from the env var named by
// [config.VaultConfig.TokenEnv] (default: "VAULT_TOKEN").
//
// TLS certificate verification follows the engine's global TLS settings.
// The Vault address must be reachable from the httpql engine process.
type vaultProvider struct {
	client  *http.Client
	address string
	mount   string
	token   string
}

// newVaultProvider constructs a vaultProvider from [config.VaultConfig].
// Returns an error when the Vault token env var is missing.
func newVaultProvider(cfg config.VaultConfig) (Provider, error) {
	tokenEnv := cfg.TokenEnv
	if tokenEnv == "" {
		tokenEnv = "VAULT_TOKEN"
	}
	token := os.Getenv(tokenEnv)
	if token == "" {
		return nil, errorf("vault", "token env var %q is not set", tokenEnv)
	}

	mount := cfg.Mount
	if mount == "" {
		mount = "secret"
	}

	address := cfg.Address
	if address == "" {
		return nil, errorf("vault", "vault.address must be configured")
	}
	address = strings.TrimRight(address, "/")

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	return &vaultProvider{
		client:  client,
		address: address,
		mount:   mount,
		token:   token,
	}, nil
}

// Lookup fetches the Vault KV v2 secret at the path derived from key.
//
// Key format: "{secret-path}/{field}" — see type documentation.
func (p *vaultProvider) Lookup(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", errorf("vault", "key must not be empty")
	}

	// Split key into Vault secret path + field name.
	lastSlash := strings.LastIndex(key, "/")
	if lastSlash < 0 {
		return "", errorf("vault", "key %q must be in the format {secret-path}/{field}", key)
	}
	secretPath := key[:lastSlash]
	field := key[lastSlash+1:]
	if secretPath == "" || field == "" {
		return "", errorf("vault", "key %q must be in the format {secret-path}/{field}", key)
	}

	// KV v2 read path: /v1/{mount}/data/{path}
	url := fmt.Sprintf("%s/v1/%s/data/%s", p.address, p.mount, secretPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", errorf("vault", "build request: %v", err)
	}
	req.Header.Set("X-Vault-Token", p.token)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", errorf("vault", "HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024)) // 1 MB max
	if err != nil {
		return "", errorf("vault", "read response body: %v", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("%w: vault secret %q not found", ErrNotFound, secretPath)
	}
	if resp.StatusCode != http.StatusOK {
		return "", errorf("vault", "unexpected status %d for %q: %s",
			resp.StatusCode, secretPath, truncate(string(body), 200))
	}

	// Parse the KV v2 response envelope.
	//
	//   { "data": { "data": { "<field>": "<value>", … } } }
	var envelope struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", errorf("vault", "parse response JSON: %v", err)
	}

	raw, ok := envelope.Data.Data[field]
	if !ok {
		return "", fmt.Errorf("%w: vault secret %q does not have field %q",
			ErrNotFound, secretPath, field)
	}

	// Accept string values only; reject unexpected types.
	switch v := raw.(type) {
	case string:
		return v, nil
	default:
		return "", errorf("vault", "field %q in secret %q is not a string (got %T)",
			field, secretPath, raw)
	}
}

// truncate caps s at maxLen with "…" to avoid logging large secrets-adjacent
// payloads.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…"
}
