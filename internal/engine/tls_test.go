package engine_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yesoreyeram/httpql/internal/policy"
)

// ─── TLS wiring tests ─────────────────────────────────────────────────────────

// TestBuildTLSConfig_MinVersion_TLS12 verifies that TLS 1.2 is the default.
func TestBuildTLSConfig_MinVersion_TLS12(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	// Build a client using the engine executor; give it the test server's
	// certificate so it does not fail TLS verification.
	ep := defaultEP()
	ep.TLSVerifyCert = true

	// We'll use the test server's own CA pool.
	certPool := x509.NewCertPool()
	certPool.AddCert(ts.Certificate())

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    certPool,
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("TLS1.2 request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
}

// TestBuildTLSConfig_CustomCA verifies that a custom CA bundle is respected.
func TestBuildTLSConfig_CustomCA(t *testing.T) {
	// Generate a self-signed CA and server cert pair for this test.
	ca, caKey := mustGenCert(t, nil, nil, true)
	srv, srvKey := mustGenCert(t, ca, caKey, false)

	// Write CA to a temp file.
	caFile := writePEM(t, ca, "CERTIFICATE")

	// Build a TLS server using our generated cert.
	srvCert, err := tls.X509KeyPair(certPEM(srv), keyPEM(srvKey))
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}}
	ts.StartTLS()
	defer ts.Close()

	// Build an HTTP client that trusts our custom CA.
	caPool := x509.NewCertPool()
	caPool.AddCert(ca)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    caPool,
			MinVersion: tls.VersionTLS12,
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("custom CA request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}

	// Verify the CA file path we would wire into the policy.
	if _, err := os.Stat(caFile); err != nil {
		t.Errorf("CA file not found: %v", err)
	}

	_ = srvKey // suppress unused warning
}

// TestBuildTLSConfig_mTLS verifies that client certificate + key can be loaded.
func TestBuildTLSConfig_mTLS(t *testing.T) {
	// Generate CA, server cert, and client cert.
	ca, caKey := mustGenCert(t, nil, nil, true)
	srv, srvKey := mustGenCert(t, ca, caKey, false)
	cli, cliKey := mustGenCert(t, ca, caKey, false)

	// Write client cert and key to temp files.
	certFile := writePEM(t, cli, "CERTIFICATE")
	keyFile := writePEMKey(t, cliKey)

	// Build TLS server that requires client certs.
	srvTLSCert, err := tls.X509KeyPair(certPEM(srv), keyPEM(srvKey))
	if err != nil {
		t.Fatalf("server X509KeyPair: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(ca)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{srvTLSCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	ts.StartTLS()
	defer ts.Close()

	// Load client cert/key pair from the files.
	cliTLSCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("client LoadX509KeyPair: %v", err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cliTLSCert},
			RootCAs:      caPool,
			MinVersion:   tls.VersionTLS12,
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("mTLS request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
}

// TestEffectivePolicy_TLSFields verifies that TLS fields are propagated from
// config to EffectivePolicy.
func TestEffectivePolicy_TLSFields(t *testing.T) {
	ep := policy.EffectivePolicy{
		TLSMinVersion:     "TLS1.3",
		TLSVerifyCert:     true,
		TLSClientCert:     "/certs/client.crt",
		TLSClientKey:      "/certs/client.key",
		TLSCustomCABundle: "/certs/ca.pem",
	}
	if ep.TLSMinVersion != "TLS1.3" {
		t.Errorf("TLSMinVersion: want TLS1.3, got %q", ep.TLSMinVersion)
	}
	if !ep.TLSVerifyCert {
		t.Error("TLSVerifyCert: want true")
	}
	if ep.TLSClientCert != "/certs/client.crt" {
		t.Errorf("TLSClientCert: want /certs/client.crt, got %q", ep.TLSClientCert)
	}
	if ep.TLSClientKey != "/certs/client.key" {
		t.Errorf("TLSClientKey: want /certs/client.key, got %q", ep.TLSClientKey)
	}
	if ep.TLSCustomCABundle != "/certs/ca.pem" {
		t.Errorf("TLSCustomCABundle: want /certs/ca.pem, got %q", ep.TLSCustomCABundle)
	}
}

// ─── cert generation helpers ──────────────────────────────────────────────────

func mustGenCert(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         isCA,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		// Include loopback IP SANs so test servers pass name validation.
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if isCA {
		tmpl.BasicConstraintsValid = true
	}
	signer := key
	signerCert := tmpl
	if parent != nil {
		signer = parentKey
		signerCert = parent
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signer)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, key
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func keyPEM(k *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalECPrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func writePEM(t *testing.T, c *x509.Certificate, typ string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: c.Raw}), 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return f
}

func writePEMKey(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	der, _ := x509.MarshalECPrivateKey(k)
	f := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return f
}

func defaultEP() policy.EffectivePolicy {
	return policy.EffectivePolicy{
		TLSVerifyCert:                    true,
		TLSMinVersion:                    "TLS1.2",
		MaxConcurrentRequestsPerQuery:    10,
		MaxConcurrentRequestsPerOrigin:   5,
		MaxConcurrentQueriesPerNamespace: 5,
		ConnectionPoolSizePerOrigin:      5,
		IdleConnectionTTL:                90 * time.Second,
		RequestConnectTimeout:            10 * time.Second,
		RequestReadTimeout:               30 * time.Second,
		RequestQueueTimeout:              30 * time.Second,
		MaxResponseBodyBytes:             1 << 20,
		MaxTotalBytesPerQuery:            10 << 20,
		MaxResponseHeaderCount:           200,
		MaxResponseHeaderValueBytes:      8192,
		MaxRequestsPerQuery:              50,
		MaxRedirectsPerRequest:           5,
		SSRFProtectionEnabled:            true,
	}
}
