package interpolate_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/yesoreyeram/httpql/internal/interpolate"
	"github.com/yesoreyeram/httpql/internal/secrets"
)

// ─── fake secrets provider ────────────────────────────────────────────────────

type mapSecrets map[string]string

func (m mapSecrets) Lookup(_ context.Context, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("%w: key %q", secrets.ErrNotFound, key)
	}
	return v, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func expand(t *testing.T, text string, sp secrets.Provider, responses map[string]interpolate.Response) string {
	t.Helper()
	out, err := interpolate.Expand(context.Background(), text, sp, responses)
	if err != nil {
		t.Fatalf("Expand(%q) unexpected error: %v", text, err)
	}
	return out
}

func expandErr(t *testing.T, text string, sp secrets.Provider, responses map[string]interpolate.Response) error {
	t.Helper()
	_, err := interpolate.Expand(context.Background(), text, sp, responses)
	if err == nil {
		t.Fatalf("Expand(%q): expected error, got nil", text)
	}
	return err
}

// ─── no-op cases ──────────────────────────────────────────────────────────────

func TestExpand_NoPlaceholders(t *testing.T) {
	got := expand(t, "hello world", nil, nil)
	if got != "hello world" {
		t.Errorf("want %q got %q", "hello world", got)
	}
}

func TestExpand_EmptyString(t *testing.T) {
	got := expand(t, "", nil, nil)
	if got != "" {
		t.Errorf("want empty, got %q", got)
	}
}

func TestExpand_UnclosedBrace(t *testing.T) {
	// Unclosed ${ is treated literally — no error.
	got := expand(t, "prefix ${secret:key", nil, nil)
	if got != "prefix ${secret:key" {
		t.Errorf("unexpected: %q", got)
	}
}

// ─── ${secret:...} ────────────────────────────────────────────────────────────

func TestExpand_SecretSimple(t *testing.T) {
	sp := mapSecrets{"MY_KEY": "supersecret"}
	got := expand(t, "${secret:MY_KEY}", sp, nil)
	if got != "supersecret" {
		t.Errorf("want supersecret, got %q", got)
	}
}

func TestExpand_SecretInLargerString(t *testing.T) {
	sp := mapSecrets{"API_KEY": "abc123"}
	got := expand(t, "Bearer ${secret:API_KEY}", sp, nil)
	if got != "Bearer abc123" {
		t.Errorf("want %q got %q", "Bearer abc123", got)
	}
}

func TestExpand_MultipleSameSecret(t *testing.T) {
	sp := mapSecrets{"K": "X"}
	got := expand(t, "${secret:K}-${secret:K}", sp, nil)
	if got != "X-X" {
		t.Errorf("want X-X got %q", got)
	}
}

func TestExpand_SecretNotFound(t *testing.T) {
	sp := mapSecrets{}
	err := expandErr(t, "${secret:MISSING}", sp, nil)
	if !secrets.IsNotFound(err) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestExpand_SecretEmptyKey(t *testing.T) {
	sp := mapSecrets{}
	err := expandErr(t, "${secret:}", sp, nil)
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestExpand_SecretNoProvider(t *testing.T) {
	err := expandErr(t, "${secret:KEY}", nil, nil)
	if err == nil {
		t.Fatal("expected error when no provider")
	}
}

// ─── ${env:...} — blocked ─────────────────────────────────────────────────────

func TestExpand_EnvRefRejected(t *testing.T) {
	err := expandErr(t, "${env:PATH}", nil, nil)
	if err == nil {
		t.Fatal("expected error for ${env:...}")
	}
	if !strings.Contains(err.Error(), "${env:...} is not allowed") {
		t.Errorf("expected 'is not allowed' in error message, got: %v", err)
	}
}

func TestExpand_EnvRefInLargerString(t *testing.T) {
	// Even embedded in a larger string the env ref must be blocked.
	err := expandErr(t, "http://example.com?token=${env:TOKEN}", nil, nil)
	if err == nil {
		t.Fatal("expected error for ${env:...}")
	}
}

// ─── ${response:...} — status ─────────────────────────────────────────────────

func TestExpand_ResponseStatus(t *testing.T) {
	responses := map[string]interpolate.Response{
		"auth": {StatusCode: 200, Headers: map[string]string{}, Body: []byte(`{}`)},
	}
	got := expand(t, "${response:auth.status}", nil, responses)
	if got != "200" {
		t.Errorf("want 200 got %q", got)
	}
}

// ─── ${response:...} — headers ────────────────────────────────────────────────

func TestExpand_ResponseHeader(t *testing.T) {
	responses := map[string]interpolate.Response{
		"auth": {StatusCode: 200, Headers: map[string]string{"X-Request-Id": "abc-123"}, Body: []byte(`{}`)},
	}
	got := expand(t, "${response:auth.header.X-Request-Id}", nil, responses)
	if got != "abc-123" {
		t.Errorf("want abc-123 got %q", got)
	}
}

func TestExpand_ResponseHeaderCaseInsensitive(t *testing.T) {
	responses := map[string]interpolate.Response{
		"step1": {StatusCode: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: []byte(`{}`)},
	}
	got := expand(t, "${response:step1.header.content-type}", nil, responses)
	if got != "application/json" {
		t.Errorf("want application/json got %q", got)
	}
}

func TestExpand_ResponseHeaderMissing(t *testing.T) {
	responses := map[string]interpolate.Response{
		"step1": {StatusCode: 200, Headers: map[string]string{}, Body: []byte(`{}`)},
	}
	err := expandErr(t, "${response:step1.header.X-Missing}", nil, responses)
	if err == nil {
		t.Fatal("expected error for missing header")
	}
}

// ─── ${response:...} — body JSON path ────────────────────────────────────────

func TestExpand_ResponseBodyTopLevel(t *testing.T) {
	body := `{"token": "mytoken123"}`
	responses := map[string]interpolate.Response{
		"auth": {StatusCode: 200, Headers: map[string]string{}, Body: []byte(body)},
	}
	got := expand(t, "${response:auth.body.token}", nil, responses)
	if got != "mytoken123" {
		t.Errorf("want mytoken123 got %q", got)
	}
}

func TestExpand_ResponseBodyNestedPath(t *testing.T) {
	body := `{"data": {"user": {"id": 42}}}`
	responses := map[string]interpolate.Response{
		"step1": {StatusCode: 200, Headers: map[string]string{}, Body: []byte(body)},
	}
	got := expand(t, "${response:step1.body.data.user.id}", nil, responses)
	if got != "42" {
		t.Errorf("want 42 got %q", got)
	}
}

func TestExpand_ResponseBodyArrayIndex(t *testing.T) {
	body := `{"items": [{"id": 1}, {"id": 99}]}`
	responses := map[string]interpolate.Response{
		"list": {StatusCode: 200, Headers: map[string]string{}, Body: []byte(body)},
	}
	got := expand(t, "${response:list.body.items[1].id}", nil, responses)
	if got != "99" {
		t.Errorf("want 99 got %q", got)
	}
}

func TestExpand_ResponseBodyStringValue(t *testing.T) {
	body := `{"greeting": "hello"}`
	responses := map[string]interpolate.Response{
		"svc": {StatusCode: 200, Headers: map[string]string{}, Body: []byte(body)},
	}
	got := expand(t, "${response:svc.body.greeting}", nil, responses)
	if got != "hello" {
		t.Errorf("want hello got %q", got)
	}
}

func TestExpand_ResponseBodyBoolValue(t *testing.T) {
	body := `{"active": true}`
	responses := map[string]interpolate.Response{
		"svc": {StatusCode: 200, Headers: map[string]string{}, Body: []byte(body)},
	}
	got := expand(t, "${response:svc.body.active}", nil, responses)
	if got != "true" {
		t.Errorf("want true got %q", got)
	}
}

func TestExpand_ResponseBodyMissingField(t *testing.T) {
	body := `{"a": 1}`
	responses := map[string]interpolate.Response{
		"svc": {StatusCode: 200, Headers: map[string]string{}, Body: []byte(body)},
	}
	err := expandErr(t, "${response:svc.body.b}", nil, responses)
	if err == nil {
		t.Fatal("expected error for missing JSON field")
	}
}

func TestExpand_ResponseBodyInvalidJSON(t *testing.T) {
	responses := map[string]interpolate.Response{
		"svc": {StatusCode: 200, Headers: map[string]string{}, Body: []byte(`not json`)},
	}
	err := expandErr(t, "${response:svc.body.field}", nil, responses)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestExpand_ResponseBodyArrayOutOfRange(t *testing.T) {
	body := `{"items": [1, 2, 3]}`
	responses := map[string]interpolate.Response{
		"svc": {StatusCode: 200, Headers: map[string]string{}, Body: []byte(body)},
	}
	err := expandErr(t, "${response:svc.body.items[10]}", nil, responses)
	if err == nil {
		t.Fatal("expected error for out of range index")
	}
}

// ─── error cases ──────────────────────────────────────────────────────────────

func TestExpand_UnknownPlaceholderType(t *testing.T) {
	err := expandErr(t, "${foo:bar}", nil, nil)
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestExpand_ResponseNoResponses(t *testing.T) {
	err := expandErr(t, "${response:auth.status}", nil, nil)
	if err == nil {
		t.Fatal("expected error when responses is nil")
	}
}

func TestExpand_ResponseNameNotFound(t *testing.T) {
	responses := map[string]interpolate.Response{}
	err := expandErr(t, "${response:missing.status}", nil, responses)
	if err == nil {
		t.Fatal("expected error for unknown request name")
	}
}

func TestExpand_ResponseMissingDot(t *testing.T) {
	err := expandErr(t, "${response:auth}", nil, map[string]interpolate.Response{"auth": {}})
	if err == nil {
		t.Fatal("expected error when no dot in response ref")
	}
}

func TestExpand_ResponseUnknownSubtype(t *testing.T) {
	responses := map[string]interpolate.Response{
		"auth": {StatusCode: 200, Headers: map[string]string{}, Body: []byte(`{}`)},
	}
	err := expandErr(t, "${response:auth.unknown}", nil, responses)
	if err == nil {
		t.Fatal("expected error for unknown subtype")
	}
}

// ─── mixed placeholders ───────────────────────────────────────────────────────

func TestExpand_SecretAndResponseMixed(t *testing.T) {
	sp := mapSecrets{"PREFIX": "Bearer"}
	responses := map[string]interpolate.Response{
		"auth": {StatusCode: 200, Headers: map[string]string{}, Body: []byte(`{"token":"tok99"}`)},
	}
	got := expand(t, "${secret:PREFIX} ${response:auth.body.token}", sp, responses)
	if got != "Bearer tok99" {
		t.Errorf("want 'Bearer tok99' got %q", got)
	}
}

// ─── CountSecretRefs ─────────────────────────────────────────────────────────

func TestCountSecretRefs(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"no placeholders", 0},
		{"${secret:A}", 1},
		{"${secret:A} and ${secret:B}", 2},
		{"${secret:A} and ${secret:A}", 2},
		{"${response:x.status}", 0},
		{"Bearer ${secret:TOKEN}", 1},
	}
	for _, tc := range cases {
		got := interpolate.CountSecretRefs(tc.in)
		if got != tc.want {
			t.Errorf("CountSecretRefs(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// ─── CountResponseRefs ───────────────────────────────────────────────────────

func TestCountResponseRefs(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"no placeholders", 0},
		{"${response:a.status}", 1},
		{"${response:a.body.id} ${response:b.header.X-Foo}", 2},
		{"${secret:K}", 0},
	}
	for _, tc := range cases {
		got := interpolate.CountResponseRefs(tc.in)
		if got != tc.want {
			t.Errorf("CountResponseRefs(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// ─── HasEnvRef ───────────────────────────────────────────────────────────────

func TestHasEnvRef(t *testing.T) {
	if !interpolate.HasEnvRef("${env:FOO}") {
		t.Error("expected HasEnvRef to return true")
	}
	if interpolate.HasEnvRef("${secret:FOO}") {
		t.Error("expected HasEnvRef to return false for ${secret:...}")
	}
	if interpolate.HasEnvRef("no placeholders") {
		t.Error("expected HasEnvRef to return false for plain text")
	}
}

// ─── JSON path extractor (via Expand) ────────────────────────────────────────

func TestExpand_JSONPath_FloatValue(t *testing.T) {
	body := `{"score": 3.14}`
	responses := map[string]interpolate.Response{
		"svc": {StatusCode: 200, Headers: map[string]string{}, Body: []byte(body)},
	}
	got := expand(t, "${response:svc.body.score}", nil, responses)
	if got != "3.14" {
		t.Errorf("want 3.14 got %q", got)
	}
}

func TestExpand_JSONPath_NullValue(t *testing.T) {
	body := `{"value": null}`
	responses := map[string]interpolate.Response{
		"svc": {StatusCode: 200, Headers: map[string]string{}, Body: []byte(body)},
	}
	got := expand(t, "${response:svc.body.value}", nil, responses)
	if got != "" {
		t.Errorf("want empty string for null, got %q", got)
	}
}

func TestExpand_JSONPath_ObjectValue(t *testing.T) {
	body := `{"meta": {"k": "v"}}`
	responses := map[string]interpolate.Response{
		"svc": {StatusCode: 200, Headers: map[string]string{}, Body: []byte(body)},
	}
	got := expand(t, "${response:svc.body.meta}", nil, responses)
	if got != `{"k":"v"}` {
		t.Errorf("want json object, got %q", got)
	}
}
