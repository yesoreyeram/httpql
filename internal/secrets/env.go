package secrets

import (
	"context"
	"fmt"
	"os"
)

// envProvider implements [Provider] by reading process environment variables.
//
// Key convention: the key is the exact name of the environment variable
// (e.g. "API_KEY", "DB_PASSWORD").  The lookup is case-sensitive on all
// platforms.
//
// This backend is suitable for development and container environments where
// secrets are injected as env vars by the container runtime or a secrets
// manager sidecar.
type envProvider struct{}

// newEnvProvider returns a Provider backed by the process environment.
func newEnvProvider() Provider {
	return &envProvider{}
}

// Lookup returns the value of the environment variable named by key.
// Returns [ErrNotFound] (wrapped) when the variable is unset or empty.
func (p *envProvider) Lookup(_ context.Context, key string) (string, error) {
	if key == "" {
		return "", errorf("env", "key must not be empty")
	}
	val, ok := os.LookupEnv(key)
	if !ok {
		return "", fmt.Errorf("%w: env var %q is not set", ErrNotFound, key)
	}
	return val, nil
}
