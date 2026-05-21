// Package secrets provides a pluggable secrets-backend abstraction for the
// httpql engine.
//
// # Provider interface
//
// All backends implement [Provider], a single-method interface:
//
//	type Provider interface {
//	    Lookup(ctx context.Context, key string) (string, error)
//	}
//
// # Key format
//
// Each backend interprets the key argument according to its own convention
// (see individual backend docs).  The engine never logs secret values —
// this is a hardcoded invariant enforced independently of the backend.
//
// # Backends
//
// | backend   | Config field              | Key convention                    |
// |-----------|---------------------------|-----------------------------------|
// | env       | (none)                    | environment-variable name         |
// | vault     | security.secrets.vault    | {secret-path}/{field}             |
// | k8s       | security.secrets.k8s      | {secret-name}/{data-key}          |
// | aws-ssm   | security.secrets.aws_ssm  | parameter name (prefix prepended) |
//
// Use [New] to construct the correct backend from [config.SecretsConfig].
package secrets

import (
	"context"
	"errors"
	"fmt"
)

// Provider resolves a named secret to its plaintext value.
//
// Implementations must be safe for concurrent use.
type Provider interface {
	// Lookup returns the plaintext value of the secret identified by key.
	//
	// Returns [ErrNotFound] (wrapped) when the key does not exist in the
	// backend.  Returns other errors for transport or auth failures.
	Lookup(ctx context.Context, key string) (string, error)
}

// ErrNotFound is returned (wrapped) when a key does not exist in the backend.
var ErrNotFound = errors.New("secret not found")

// IsNotFound reports whether err is or wraps [ErrNotFound].
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// errorf is a small helper that formats a provider-specific error message.
func errorf(backend, format string, args ...any) error {
	return fmt.Errorf("secrets[%s]: %s", backend, fmt.Sprintf(format, args...))
}
