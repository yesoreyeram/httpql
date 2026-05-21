package secrets

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yesoreyeram/httpql/internal/config"
)

// k8sProvider implements [Provider] using the Kubernetes Secrets API.
// No third-party SDK is required; authentication uses the pod's service
// account bearer token.
//
// Key convention: "{secret-name}/{data-key}"
//
//   - secret-name: the name of the Kubernetes Secret object
//   - data-key: the key within the Secret's data map
//
// Example: key "db-credentials/password" resolves as:
//
//	GET {k8s_api_host}/api/v1/namespaces/{namespace}/secrets/db-credentials
//	→ base64-decode(response.data["password"])
//
// The namespace is read from [config.K8sConfig.Namespace], defaulting to the
// pod's own namespace (read from the well-known file
// /var/run/secrets/kubernetes.io/serviceaccount/namespace).
//
// The service account token is read from [config.K8sConfig.ServiceAccountTokenPath]
// (default: /var/run/secrets/kubernetes.io/serviceaccount/token).
//
// The Kubernetes API CA bundle is read from
// /var/run/secrets/kubernetes.io/serviceaccount/ca.crt when present; otherwise
// TLS defaults are used (suitable for external clusters with a valid cert).
type k8sProvider struct {
	client     *http.Client
	apiBase    string // e.g. "https://kubernetes.default.svc"
	namespace  string
	saToken    string
}

const (
	k8sDefaultAPIHost   = "https://kubernetes.default.svc"
	k8sTokenPath        = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	k8sNamespacePath    = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	k8sCACertPath       = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// newK8sProvider constructs a k8sProvider from [config.K8sConfig].
func newK8sProvider(cfg config.K8sConfig) (Provider, error) {
	tokenPath := cfg.ServiceAccountTokenPath
	if tokenPath == "" {
		tokenPath = k8sTokenPath
	}
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, errorf("k8s", "read service account token from %q: %v", tokenPath, err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return nil, errorf("k8s", "service account token at %q is empty", tokenPath)
	}

	ns := cfg.Namespace
	if ns == "" {
		// Fall back to pod's own namespace from the service account projection.
		data, err := os.ReadFile(k8sNamespacePath)
		if err != nil {
			return nil, errorf("k8s", "k8s.namespace not configured and cannot read %q: %v",
				k8sNamespacePath, err)
		}
		ns = strings.TrimSpace(string(data))
	}
	if ns == "" {
		return nil, errorf("k8s", "namespace could not be determined")
	}

	// Build TLS config; use the pod CA cert when available.
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if _, err := os.Stat(k8sCACertPath); err == nil {
		// Best-effort: use the cluster CA to verify the API server certificate.
		caCert, err := os.ReadFile(k8sCACertPath)
		if err == nil && len(caCert) > 0 {
			pool, loadErr := loadCertPool(caCert)
			if loadErr == nil {
				tlsCfg.RootCAs = pool
			}
		}
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	return &k8sProvider{
		client:    client,
		apiBase:   k8sDefaultAPIHost,
		namespace: ns,
		saToken:   token,
	}, nil
}

// Lookup fetches a Kubernetes Secret and returns the value for the requested
// data key.
//
// Key format: "{secret-name}/{data-key}" — see type documentation.
func (p *k8sProvider) Lookup(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", errorf("k8s", "key must not be empty")
	}

	slash := strings.Index(key, "/")
	if slash < 0 {
		return "", errorf("k8s",
			"key %q must be in the format {secret-name}/{data-key}", key)
	}
	secretName := key[:slash]
	dataKey := key[slash+1:]
	if secretName == "" || dataKey == "" {
		return "", errorf("k8s",
			"key %q must be in the format {secret-name}/{data-key}", key)
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s",
		p.apiBase, p.namespace, secretName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", errorf("k8s", "build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.saToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", errorf("k8s", "HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return "", errorf("k8s", "read response body: %v", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("%w: k8s secret %q not found in namespace %q",
			ErrNotFound, secretName, p.namespace)
	}
	if resp.StatusCode != http.StatusOK {
		return "", errorf("k8s", "unexpected status %d for secret %q: %s",
			resp.StatusCode, secretName, truncate(string(body), 200))
	}

	// Kubernetes Secret JSON: { "data": { "<key>": "<base64-value>" } }
	var secret struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(body, &secret); err != nil {
		return "", errorf("k8s", "parse response JSON: %v", err)
	}

	encoded, ok := secret.Data[dataKey]
	if !ok {
		return "", fmt.Errorf("%w: k8s secret %q does not have key %q",
			ErrNotFound, secretName, dataKey)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", errorf("k8s", "base64-decode secret %q key %q: %v",
			secretName, dataKey, err)
	}

	return string(decoded), nil
}
