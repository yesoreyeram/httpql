package secrets

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yesoreyeram/httpql/internal/config"
)

// awsSsmProvider implements [Provider] using the AWS Systems Manager (SSM)
// Parameter Store API.  No third-party SDK is required; authentication uses
// AWS Signature Version 4 (SigV4) computed from standard AWS credential env
// vars.
//
// Key convention: the key is the parameter name.  When [config.AWSSMConfig.Prefix]
// is set (e.g. "/httpql/"), it is prepended automatically.  If the key already
// starts with the prefix, it is not prepended again.
//
// Example: with prefix "/httpql/" and key "db/password", the resolved
// parameter name is "/httpql/db/password".
//
// Credentials are read from standard AWS environment variables:
//
//	AWS_ACCESS_KEY_ID
//	AWS_SECRET_ACCESS_KEY
//	AWS_SESSION_TOKEN  (optional; required for temporary credentials)
//
// The region is read from [config.AWSSMConfig.Region] or the
// AWS_DEFAULT_REGION / AWS_REGION environment variable.
type awsSsmProvider struct {
	client    *http.Client
	endpoint  string
	region    string
	prefix    string
	accessKey string
	secretKey string
	sessionToken string
}

// newAwsSsmProvider constructs an awsSsmProvider from [config.AWSSMConfig].
func newAwsSsmProvider(cfg config.AWSSMConfig) (Provider, error) {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	sessionToken := os.Getenv("AWS_SESSION_TOKEN")

	if accessKey == "" || secretKey == "" {
		return nil, errorf("aws-ssm",
			"AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set")
	}

	region := cfg.Region
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		return nil, errorf("aws-ssm",
			"region must be configured via aws_ssm.region or AWS_DEFAULT_REGION / AWS_REGION")
	}

	return &awsSsmProvider{
		client: &http.Client{Timeout: 10 * time.Second},
		endpoint: fmt.Sprintf("https://ssm.%s.amazonaws.com", region),
		region:   region,
		prefix:   cfg.Prefix,
		accessKey:    accessKey,
		secretKey:    secretKey,
		sessionToken: sessionToken,
	}, nil
}

// Lookup retrieves a parameter from AWS SSM Parameter Store.
//
// Key format: parameter name (prefix is prepended automatically).
func (p *awsSsmProvider) Lookup(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", errorf("aws-ssm", "key must not be empty")
	}

	// Prepend prefix if not already present.
	name := key
	if p.prefix != "" && !strings.HasPrefix(key, p.prefix) {
		name = p.prefix + key
	}

	// Build SSM GetParameter request using the JSON API.
	// POST https://ssm.{region}.amazonaws.com/
	// X-Amz-Target: AmazonSSM.GetParameter
	// Body: {"Name":"...","WithDecryption":true}
	payload := fmt.Sprintf(`{"Name":%q,"WithDecryption":true}`, name)

	now := time.Now().UTC()
	dateStr := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	body := strings.NewReader(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/", body)
	if err != nil {
		return "", errorf("aws-ssm", "build request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AmazonSSM.GetParameter")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Host", fmt.Sprintf("ssm.%s.amazonaws.com", p.region))
	if p.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", p.sessionToken)
	}

	// Sign the request with SigV4.
	sig := p.sigV4(
		dateStr, amzDate, "POST",
		"/", "",
		req.Header, []byte(payload),
	)
	req.Header.Set("Authorization", sig)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", errorf("aws-ssm", "HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return "", errorf("aws-ssm", "read response body: %v", err)
	}

	// 400 with ParameterNotFound → ErrNotFound
	if resp.StatusCode == http.StatusBadRequest {
		var errResp struct {
			Code    string `json:"__type"`
			Message string `json:"message"`
		}
		if json.Unmarshal(respBody, &errResp) == nil &&
			strings.Contains(errResp.Code, "ParameterNotFound") {
			return "", fmt.Errorf("%w: aws-ssm parameter %q not found", ErrNotFound, name)
		}
	}
	if resp.StatusCode != http.StatusOK {
		return "", errorf("aws-ssm", "unexpected status %d for parameter %q: %s",
			resp.StatusCode, name, truncate(string(respBody), 200))
	}

	var result struct {
		Parameter struct {
			Value string `json:"Value"`
		} `json:"Parameter"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", errorf("aws-ssm", "parse response JSON: %v", err)
	}
	return result.Parameter.Value, nil
}

// ─── AWS SigV4 implementation ─────────────────────────────────────────────────

// sigV4 returns the Authorization header value for an AWS SigV4 signed
// request.  This is a minimal implementation covering the needs of the SSM
// GetParameter API call (POST, application/x-amz-json-1.1, single host).
func (p *awsSsmProvider) sigV4(
	dateStr, amzDate, method, path, query string,
	headers http.Header, payload []byte,
) string {
	service := "ssm"

	// ── Step 1: Canonical request ─────────────────────────────────────────
	// Only sign the headers we set explicitly.
	signedHeaderNames := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if p.sessionToken != "" {
		signedHeaderNames = append(signedHeaderNames, "x-amz-security-token")
	}
	signedHeadersStr := strings.Join(signedHeaderNames, ";")

	canonicalHeaders := ""
	for _, h := range signedHeaderNames {
		canonicalHeaders += h + ":" + strings.TrimSpace(headers.Get(toHTTPHeader(h))) + "\n"
	}

	payloadHash := hexHash(payload)

	canonicalRequest := strings.Join([]string{
		method,
		path,
		query,
		canonicalHeaders,
		signedHeadersStr,
		payloadHash,
	}, "\n")

	// ── Step 2: String to sign ────────────────────────────────────────────
	credScope := dateStr + "/" + p.region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		hexHash([]byte(canonicalRequest)),
	}, "\n")

	// ── Step 3: Signing key ───────────────────────────────────────────────
	kDate := hmacSHA256([]byte("AWS4"+p.secretKey), []byte(dateStr))
	kRegion := hmacSHA256(kDate, []byte(p.region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	// ── Step 4: Signature ─────────────────────────────────────────────────
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	return fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		p.accessKey, credScope, signedHeadersStr, signature,
	)
}

func hexHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// toHTTPHeader converts a lowercase header name to the canonical HTTP form
// accepted by http.Header.Get (which is case-insensitive in Go).
// We just return the key unchanged — http.Header.Get lowercases internally.
func toHTTPHeader(lower string) string {
	return lower
}
