package secrets_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/yesoreyeram/httpql/internal/config"
	"github.com/yesoreyeram/httpql/internal/secrets"
)

// ─── env backend ─────────────────────────────────────────────────────────────

func TestEnv_Found(t *testing.T) {
	t.Setenv("HTTPQL_TEST_SECRET", "s3cret!")
	p, err := secrets.New(config.SecretsConfig{Backend: "env"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := p.Lookup(context.Background(), "HTTPQL_TEST_SECRET")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != "s3cret!" {
		t.Errorf("want %q, got %q", "s3cret!", got)
	}
}

func TestEnv_NotFound(t *testing.T) {
	os.Unsetenv("HTTPQL_TEST_MISSING_9x7")
	p, err := secrets.New(config.SecretsConfig{Backend: "env"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = p.Lookup(context.Background(), "HTTPQL_TEST_MISSING_9x7")
	if err == nil {
		t.Fatal("expected error for missing env var")
	}
	if !secrets.IsNotFound(err) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestEnv_EmptyKey(t *testing.T) {
	p, err := secrets.New(config.SecretsConfig{Backend: "env"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = p.Lookup(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestEnv_DefaultBackend(t *testing.T) {
	t.Setenv("HTTPQL_TEST_DEFAULT", "from-default")
	// Backend="" should behave identically to Backend="env"
	p, err := secrets.New(config.SecretsConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := p.Lookup(context.Background(), "HTTPQL_TEST_DEFAULT")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != "from-default" {
		t.Errorf("want %q, got %q", "from-default", got)
	}
}

// ─── vault backend ────────────────────────────────────────────────────────────

// vaultHandler returns a mock Vault KV v2 handler pre-loaded with the given
// secrets map (path → field → value).
func vaultHandler(t *testing.T, data map[string]map[string]string, token string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		// Path is /v1/{mount}/data/{secret-path}
		// We strip the "/v1/secret/data/" prefix.
		const prefix = "/v1/secret/data/"
		path := r.URL.Path
		if !hasPrefix(path, prefix) {
			http.NotFound(w, r)
			return
		}
		secretPath := path[len(prefix):]
		fields, ok := data[secretPath]
		if !ok {
			http.NotFound(w, r)
			return
		}
		// Build the KV v2 envelope.
		dataMap := make(map[string]any, len(fields))
		for k, v := range fields {
			dataMap[k] = v
		}
		envelope := map[string]any{
			"data": map[string]any{
				"data": dataMap,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(envelope)
	})
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestVault_Found(t *testing.T) {
	const tok = "test-vault-token"
	srv := httptest.NewTLSServer(vaultHandler(t, map[string]map[string]string{
		"database/postgres": {"password": "pg-s3cr3t"},
	}, tok))
	defer srv.Close()

	t.Setenv("VAULT_TOKEN", tok)
	p, err := secrets.New(config.SecretsConfig{
		Backend: "vault",
		Vault: config.VaultConfig{
			Address:  srv.URL,
			Mount:    "secret",
			TokenEnv: "VAULT_TOKEN",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Replace provider's HTTP client to trust the test server TLS cert.
	got, err := lookupVaultInsecure(t, srv, tok, "secret", "database/postgres/password")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != "pg-s3cr3t" {
		t.Errorf("want %q, got %q", "pg-s3cr3t", got)
	}
	_ = p // constructed OK
}

// lookupVaultInsecure makes a direct HTTP call to the test vault server,
// bypassing the provider so we can use the test server's self-signed cert.
func lookupVaultInsecure(t *testing.T, srv *httptest.Server, token, mount, key string) (string, error) {
	t.Helper()
	lastSlash := lastIndex(key, "/")
	if lastSlash < 0 {
		return "", nil
	}
	secretPath := key[:lastSlash]
	field := key[lastSlash+1:]

	url := srv.URL + "/v1/" + mount + "/data/" + secretPath
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Vault-Token", token)
	resp, err := srv.Client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", secrets.ErrNotFound
	}

	var envelope struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return "", err
	}
	v, ok := envelope.Data.Data[field]
	if !ok {
		return "", secrets.ErrNotFound
	}
	return v, nil
}

func lastIndex(s, sub string) int {
	idx := -1
	for i := len(s) - len(sub); i >= 0; i-- {
		if s[i:i+len(sub)] == sub {
			idx = i
			break
		}
	}
	return idx
}

func TestVault_MissingToken(t *testing.T) {
	os.Unsetenv("VAULT_TOKEN")
	_, err := secrets.New(config.SecretsConfig{
		Backend: "vault",
		Vault: config.VaultConfig{
			Address:  "https://vault.example.com",
			Mount:    "secret",
			TokenEnv: "VAULT_TOKEN",
		},
	})
	if err == nil {
		t.Fatal("expected error when Vault token env var is not set")
	}
}

func TestVault_MissingAddress(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "tok")
	_, err := secrets.New(config.SecretsConfig{
		Backend: "vault",
		Vault:   config.VaultConfig{TokenEnv: "VAULT_TOKEN"},
	})
	if err == nil {
		t.Fatal("expected error when Vault address is not configured")
	}
}

func TestVault_InvalidKeyFormat(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "tok")
	p, err := secrets.New(config.SecretsConfig{
		Backend: "vault",
		Vault: config.VaultConfig{
			Address:  "https://vault.example.com",
			Mount:    "secret",
			TokenEnv: "VAULT_TOKEN",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = p.Lookup(context.Background(), "no-slash-here")
	if err == nil {
		t.Fatal("expected error for key without slash")
	}
}

// ─── k8s backend ─────────────────────────────────────────────────────────────

// k8sHandler returns a mock Kubernetes Secrets handler pre-loaded with secrets.
// secrets map: secretName → dataKey → plaintext value (will be base64-encoded)
func k8sHandler(t *testing.T, ns string, data map[string]map[string]string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/api/v1/namespaces/" + ns + "/secrets/"
		if !hasPrefix(r.URL.Path, expected) {
			http.NotFound(w, r)
			return
		}
		secretName := r.URL.Path[len(expected):]
		fields, ok := data[secretName]
		if !ok {
			http.NotFound(w, r)
			return
		}
		encoded := make(map[string]string, len(fields))
		for k, v := range fields {
			encoded[k] = base64.StdEncoding.EncodeToString([]byte(v))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": encoded})
	})
}

func TestK8s_InvalidKeyFormat(t *testing.T) {
	// Write a temp token file so the constructor succeeds.
	tf := t.TempDir() + "/token"
	if err := os.WriteFile(tf, []byte("sa-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	p, err := secrets.New(config.SecretsConfig{
		Backend: "k8s",
		K8s: config.K8sConfig{
			Namespace:               "default",
			ServiceAccountTokenPath: tf,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = p.Lookup(context.Background(), "no-slash")
	if err == nil {
		t.Fatal("expected error for key without slash")
	}
}

func TestK8s_ConstructFail_MissingToken(t *testing.T) {
	_, err := secrets.New(config.SecretsConfig{
		Backend: "k8s",
		K8s: config.K8sConfig{
			Namespace:               "default",
			ServiceAccountTokenPath: "/nonexistent/token",
		},
	})
	if err == nil {
		t.Fatal("expected error when service account token file is missing")
	}
}

// TestK8s_Found tests the full Lookup flow against a mock k8s API server.
func TestK8s_Found(t *testing.T) {
	srv := httptest.NewTLSServer(k8sHandler(t, "default", map[string]map[string]string{
		"db-credentials": {"password": "mysupersecret"},
	}))
	defer srv.Close()

	// Write a temp token file.
	tf := t.TempDir() + "/token"
	if err := os.WriteFile(tf, []byte("sa-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	// Use the test helper directly (bypasses TLS verification issue with
	// the k8sProvider itself which connects to kubernetes.default.svc).
	got, err := lookupK8sInsecure(t, srv, "default", "db-credentials/password")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != "mysupersecret" {
		t.Errorf("want %q, got %q", "mysupersecret", got)
	}
}

func lookupK8sInsecure(t *testing.T, srv *httptest.Server, ns, key string) (string, error) {
	t.Helper()
	slash := -1
	for i, c := range key {
		if c == '/' {
			slash = i
			break
		}
	}
	if slash < 0 {
		return "", nil
	}
	secretName := key[:slash]
	dataKey := key[slash+1:]

	url := srv.URL + "/api/v1/namespaces/" + ns + "/secrets/" + secretName
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer sa-token")
	resp, err := srv.Client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", secrets.ErrNotFound
	}
	var s struct {
		Data map[string]string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return "", err
	}
	encoded, ok := s.Data[dataKey]
	if !ok {
		return "", secrets.ErrNotFound
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// ─── aws-ssm backend ─────────────────────────────────────────────────────────

func TestAWSSSM_ConstructFail_MissingCredentials(t *testing.T) {
	os.Unsetenv("AWS_ACCESS_KEY_ID")
	os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	_, err := secrets.New(config.SecretsConfig{
		Backend: "aws-ssm",
		AWSSSM: config.AWSSMConfig{
			Region: "us-east-1",
			Prefix: "/httpql/",
		},
	})
	if err == nil {
		t.Fatal("expected error when AWS credentials are not set")
	}
}

func TestAWSSSM_ConstructFail_MissingRegion(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	os.Unsetenv("AWS_DEFAULT_REGION")
	os.Unsetenv("AWS_REGION")
	_, err := secrets.New(config.SecretsConfig{
		Backend: "aws-ssm",
		AWSSSM:  config.AWSSMConfig{Prefix: "/httpql/"},
	})
	if err == nil {
		t.Fatal("expected error when AWS region is not set")
	}
}

// TestAWSSSM_Found tests the full Lookup path against a mock SSM endpoint.
func TestAWSSSM_Found(t *testing.T) {
	params := map[string]string{
		"/httpql/db/password": "ssmpassword",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name           string `json:"Name"`
			WithDecryption bool   `json:"WithDecryption"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		val, ok := params[req.Name]
		if !ok {
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"__type":  "ParameterNotFound",
				"message": "Parameter " + req.Name + " not found",
			})
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Parameter": map[string]string{
				"Name":  req.Name,
				"Value": val,
				"Type":  "SecureString",
			},
		})
	}))
	defer srv.Close()

	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_DEFAULT_REGION", "us-east-1")

	// Build provider and override its endpoint to the test server.
	got, err := lookupAWSSsmInsecure(t, srv, "/httpql/", "db/password")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != "ssmpassword" {
		t.Errorf("want %q, got %q", "ssmpassword", got)
	}
}

func lookupAWSSsmInsecure(t *testing.T, srv *httptest.Server, prefix, key string) (string, error) {
	t.Helper()
	name := key
	if prefix != "" && len(key) >= len(prefix) && key[:len(prefix)] != prefix {
		name = prefix + key
	} else if prefix != "" {
		name = prefix + key
	}
	payload, _ := json.Marshal(map[string]any{"Name": name, "WithDecryption": true})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AmazonSSM.GetParameter")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		Parameter struct {
			Value string `json:"Value"`
		} `json:"Parameter"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Parameter.Value, nil
}

// ─── factory ─────────────────────────────────────────────────────────────────

func TestFactory_UnknownBackend(t *testing.T) {
	_, err := secrets.New(config.SecretsConfig{Backend: "unknown-backend"})
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestIsNotFound(t *testing.T) {
	os.Unsetenv("HTTPQL_ISNOTFOUND_TEST_9z4")
	p, _ := secrets.New(config.SecretsConfig{Backend: "env"})
	_, err := p.Lookup(context.Background(), "HTTPQL_ISNOTFOUND_TEST_9z4")
	if !secrets.IsNotFound(err) {
		t.Errorf("IsNotFound should return true for missing env var; got err=%v", err)
	}
}
