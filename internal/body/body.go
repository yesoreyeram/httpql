// Package body provides composable builders for HTTP request bodies.
//
// Each type in this package implements the [Provider] interface, which
// serialises a structured value into raw bytes and returns the matching
// Content-Type header value.  The engine.Request struct accepts an optional
// BodyProvider so callers never have to handle serialisation manually.
//
// Supported body methods
//
//	Method             Type             Content-Type
//	─────────────────────────────────────────────────────────────────────
//	Raw bytes          Raw              caller-supplied
//	JSON               JSON             application/json
//	URL-encoded form   Form             application/x-www-form-urlencoded
//	Multipart form     Multipart        multipart/form-data; boundary=…
//	GraphQL            GraphQL          application/json
//	XML                XML              application/xml
//	Plain text         Text             text/plain; charset=utf-8
package body

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"strings"
)

// Provider builds an HTTP request body.
// Build returns the encoded body bytes, the content-type string (e.g.
// "application/json"), and any encoding error.
type Provider interface {
	Build() (body []byte, contentType string, err error)
}

// ─────────────────────────────────────────────────────────────────────────────
// Raw
// ─────────────────────────────────────────────────────────────────────────────

// Raw sends pre-serialised bytes with an explicit Content-Type.
// Use this when you have already built the payload and only need the engine to
// enforce guard rails.
//
//	p := body.Raw{ContentType: "application/octet-stream", Data: myBytes}
type Raw struct {
	// ContentType is the Content-Type header value, e.g. "application/json".
	ContentType string
	// Data is the raw body payload.
	Data []byte
}

// Build implements Provider.
func (r Raw) Build() ([]byte, string, error) {
	ct := r.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	return r.Data, ct, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON
// ─────────────────────────────────────────────────────────────────────────────

// JSON serialises Value as JSON (application/json).
// Value may be any Go type supported by encoding/json.
//
//	p := body.JSON{Value: map[string]any{"key": "value"}}
type JSON struct {
	// Value is marshalled by encoding/json.Marshal.
	Value any
}

// Build implements Provider.
func (j JSON) Build() ([]byte, string, error) {
	b, err := json.Marshal(j.Value)
	if err != nil {
		return nil, "", fmt.Errorf("body.JSON: marshal: %w", err)
	}
	return b, "application/json", nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Form
// ─────────────────────────────────────────────────────────────────────────────

// Form encodes Values as an application/x-www-form-urlencoded body (the
// classic HTML form post format).
//
//	p := body.Form{Values: url.Values{"q": {"go"}, "page": {"1"}}}
type Form struct {
	// Values is the set of key-value pairs to encode.
	Values url.Values
}

// Build implements Provider.
func (f Form) Build() ([]byte, string, error) {
	if f.Values == nil {
		return []byte{}, "application/x-www-form-urlencoded", nil
	}
	return []byte(f.Values.Encode()), "application/x-www-form-urlencoded", nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Multipart
// ─────────────────────────────────────────────────────────────────────────────

// Part is a single part in a multipart/form-data body.
//
//   - Text fields: set Name and Data; leave Filename and ContentType empty.
//   - File uploads: set Name, Filename, ContentType, and Data.
type Part struct {
	// Name is the form field name (required).
	Name string
	// Filename is the file name for file-upload parts.
	// If non-empty, a "Content-Disposition: form-data; filename=…" header is set.
	Filename string
	// ContentType is the MIME type for file parts (e.g. "image/png").
	// Defaults to "application/octet-stream" when Filename is non-empty and
	// ContentType is empty.
	ContentType string
	// Data is the raw bytes of the part.
	Data []byte
}

// Multipart builds a multipart/form-data body.
//
//	p := body.Multipart{Parts: []body.Part{
//	    {Name: "username", Data: []byte("alice")},
//	    {Name: "avatar", Filename: "photo.png", ContentType: "image/png", Data: imgBytes},
//	}}
type Multipart struct {
	Parts []Part
}

// Build implements Provider.
func (m Multipart) Build() ([]byte, string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	for i, p := range m.Parts {
		if p.Name == "" {
			return nil, "", fmt.Errorf("body.Multipart: part %d: Name is required", i)
		}

		var (
			pw  io.Writer
			err error
		)

		if p.Filename != "" {
			// File part: set a Content-Type MIME header.
			ct := p.ContentType
			if ct == "" {
				ct = "application/octet-stream"
			}
			h := make(textproto.MIMEHeader)
			h.Set("Content-Disposition",
				fmt.Sprintf(`form-data; name=%q; filename=%q`, p.Name, p.Filename))
			h.Set("Content-Type", ct)
			pw, err = mw.CreatePart(h)
		} else {
			pw, err = mw.CreateFormField(p.Name)
		}
		if err != nil {
			return nil, "", fmt.Errorf("body.Multipart: part %q: create: %w", p.Name, err)
		}
		if _, err = pw.Write(p.Data); err != nil {
			return nil, "", fmt.Errorf("body.Multipart: part %q: write: %w", p.Name, err)
		}
	}

	if err := mw.Close(); err != nil {
		return nil, "", fmt.Errorf("body.Multipart: close writer: %w", err)
	}
	return buf.Bytes(), mw.FormDataContentType(), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// GraphQL
// ─────────────────────────────────────────────────────────────────────────────

// graphQLPayload is the JSON wire format for a GraphQL request body.
type graphQLPayload struct {
	Query         string         `json:"query"`
	OperationName string         `json:"operationName,omitempty"`
	Variables     map[string]any `json:"variables,omitempty"`
}

// GraphQL builds a JSON body conforming to the GraphQL-over-HTTP specification
// (application/json with a {"query","operationName","variables"} payload).
//
//	p := body.GraphQL{
//	    Query:     "query GetUser($id: ID!) { user(id: $id) { name } }",
//	    Variables: map[string]any{"id": "42"},
//	}
type GraphQL struct {
	// Query is the GraphQL document string (required).
	Query string
	// OperationName selects which operation to run when Query defines multiple.
	OperationName string
	// Variables is the JSON-serialisable variables map.
	Variables map[string]any
}

// Build implements Provider.
func (g GraphQL) Build() ([]byte, string, error) {
	if strings.TrimSpace(g.Query) == "" {
		return nil, "", fmt.Errorf("body.GraphQL: Query must not be empty")
	}
	p := graphQLPayload{
		Query:         g.Query,
		OperationName: g.OperationName,
		Variables:     g.Variables,
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, "", fmt.Errorf("body.GraphQL: marshal: %w", err)
	}
	return b, "application/json", nil
}

// ─────────────────────────────────────────────────────────────────────────────
// XML
// ─────────────────────────────────────────────────────────────────────────────

// XML sends a pre-built or Go-struct-encoded XML body (application/xml).
// Exactly one of Data or Value must be set.
//
//	// Pre-built bytes:
//	p := body.XML{Data: []byte(`<root><item>1</item></root>`)}
//
//	// Auto-encoded struct:
//	type Root struct {
//	    XMLName xml.Name `xml:"root"`
//	    Item    int      `xml:"item"`
//	}
//	p := body.XML{Value: Root{Item: 1}}
type XML struct {
	// Data is a pre-serialised XML document.  Mutually exclusive with Value.
	Data []byte
	// Value is a Go value encoded via encoding/xml.Marshal.  Mutually exclusive
	// with Data.
	Value any
}

// Build implements Provider.
func (x XML) Build() ([]byte, string, error) {
	if x.Data != nil && x.Value != nil {
		return nil, "", fmt.Errorf("body.XML: set either Data or Value, not both")
	}
	if x.Data != nil {
		return x.Data, "application/xml", nil
	}
	if x.Value != nil {
		b, err := xml.Marshal(x.Value)
		if err != nil {
			return nil, "", fmt.Errorf("body.XML: marshal: %w", err)
		}
		return b, "application/xml", nil
	}
	return []byte{}, "application/xml", nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Text
// ─────────────────────────────────────────────────────────────────────────────

// Text sends a UTF-8 plain-text body (text/plain; charset=utf-8).
//
//	p := body.Text{Data: []byte("hello, world")}
type Text struct {
	Data []byte
}

// Build implements Provider.
func (t Text) Build() ([]byte, string, error) {
	return t.Data, "text/plain; charset=utf-8", nil
}
