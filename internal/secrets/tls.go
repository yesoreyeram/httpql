package secrets

import (
	"crypto/x509"
	"fmt"
)

// loadCertPool creates an x509.CertPool from the given PEM-encoded CA cert
// bytes.  Returns an error when the pool cannot be created or the certificate
// cannot be added.
func loadCertPool(caCert []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("secrets: could not append CA certificate to pool")
	}
	return pool, nil
}
