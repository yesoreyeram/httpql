package body_test

import (
	"encoding/json"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
	"testing"

	"github.com/yesoreyeram/httpql/internal/body"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func mustBuild(t *testing.T, p body.Provider) ([]byte, string) {
	t.Helper()
	b, ct, err := p.Build()
	if err != nil {
		t.Fatalf("unexpected Build error: %v", err)
	}
	return b, ct
}

func assertContentType(t *testing.T, got, want string) {
	t.Helper()
	// Compare only the media type, ignoring parameters like boundary=.
	mt, _, err := mime.ParseMediaType(got)
	if err != nil {
		t.Fatalf("ParseMediaType(%q): %v", got, err)
	}
	wantMT, _, _ := mime.ParseMediaType(want)
	if mt != wantMT {
		t.Errorf("content-type media type: got %q, want %q (full: %q)", mt, wantMT, got)
	}
}

// ─── Raw ─────────────────────────────────────────────────────────────────────

func TestRaw_Build(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		provider    body.Raw
		wantBody    string
		wantCT      string
	}{
		{
			name:     "explicit content-type",
			provider: body.Raw{ContentType: "application/json", Data: []byte(`{"a":1}`)},
			wantBody: `{"a":1}`,
			wantCT:   "application/json",
		},
		{
			name:     "empty content-type defaults to octet-stream",
			provider: body.Raw{Data: []byte{0x01, 0x02}},
			wantBody: "\x01\x02",
			wantCT:   "application/octet-stream",
		},
		{
			name:     "nil data produces empty body",
			provider: body.Raw{ContentType: "text/plain"},
			wantBody: "",
			wantCT:   "text/plain",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, ct, err := tc.provider.Build()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(b) != tc.wantBody {
				t.Errorf("body: got %q, want %q", b, tc.wantBody)
			}
			assertContentType(t, ct, tc.wantCT)
		})
	}
}

// ─── JSON ─────────────────────────────────────────────────────────────────────

func TestJSON_Build(t *testing.T) {
	t.Parallel()

	t.Run("map value", func(t *testing.T) {
		t.Parallel()
		p := body.JSON{Value: map[string]any{"hello": "world", "n": 42}}
		b, ct := mustBuild(t, p)
		assertContentType(t, ct, "application/json")

		var got map[string]any
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got["hello"] != "world" {
			t.Errorf(`expected hello="world", got %v`, got["hello"])
		}
		if got["n"] != float64(42) {
			t.Errorf("expected n=42, got %v", got["n"])
		}
	})

	t.Run("struct value", func(t *testing.T) {
		t.Parallel()
		type payload struct {
			Name  string `json:"name"`
			Score int    `json:"score"`
		}
		p := body.JSON{Value: payload{Name: "alice", Score: 99}}
		b, ct := mustBuild(t, p)
		assertContentType(t, ct, "application/json")
		if !strings.Contains(string(b), `"alice"`) {
			t.Errorf("expected alice in JSON, got %s", b)
		}
	})

	t.Run("nil value produces null", func(t *testing.T) {
		t.Parallel()
		p := body.JSON{Value: nil}
		b, ct := mustBuild(t, p)
		assertContentType(t, ct, "application/json")
		if string(b) != "null" {
			t.Errorf("expected null, got %s", b)
		}
	})

	t.Run("unmarshalable value returns error", func(t *testing.T) {
		t.Parallel()
		// channels cannot be marshalled to JSON
		p := body.JSON{Value: make(chan int)}
		_, _, err := p.Build()
		if err == nil {
			t.Fatal("expected error for channel value")
		}
	})
}

// ─── Form ─────────────────────────────────────────────────────────────────────

func TestForm_Build(t *testing.T) {
	t.Parallel()

	t.Run("basic key-value pairs", func(t *testing.T) {
		t.Parallel()
		p := body.Form{Values: url.Values{
			"username": {"alice"},
			"password": {"s3cr3t"},
		}}
		b, ct := mustBuild(t, p)
		assertContentType(t, ct, "application/x-www-form-urlencoded")

		parsed, err := url.ParseQuery(string(b))
		if err != nil {
			t.Fatalf("ParseQuery: %v", err)
		}
		if parsed.Get("username") != "alice" {
			t.Errorf("username: got %q", parsed.Get("username"))
		}
		if parsed.Get("password") != "s3cr3t" {
			t.Errorf("password: got %q", parsed.Get("password"))
		}
	})

	t.Run("special characters are percent-encoded", func(t *testing.T) {
		t.Parallel()
		p := body.Form{Values: url.Values{"q": {"hello world & more=1"}}}
		b, _ := mustBuild(t, p)
		if strings.Contains(string(b), " ") {
			t.Errorf("space should be encoded, got %q", b)
		}
	})

	t.Run("multi-value key", func(t *testing.T) {
		t.Parallel()
		p := body.Form{Values: url.Values{"color": {"red", "blue", "green"}}}
		b, _ := mustBuild(t, p)
		parsed, _ := url.ParseQuery(string(b))
		if len(parsed["color"]) != 3 {
			t.Errorf("expected 3 color values, got %v", parsed["color"])
		}
	})

	t.Run("nil Values produces empty body", func(t *testing.T) {
		t.Parallel()
		p := body.Form{Values: nil}
		b, ct := mustBuild(t, p)
		assertContentType(t, ct, "application/x-www-form-urlencoded")
		if len(b) != 0 {
			t.Errorf("expected empty body, got %q", b)
		}
	})
}

// ─── Multipart ────────────────────────────────────────────────────────────────

func TestMultipart_Build(t *testing.T) {
	t.Parallel()

	t.Run("text field only", func(t *testing.T) {
		t.Parallel()
		p := body.Multipart{Parts: []body.Part{
			{Name: "message", Data: []byte("hello")},
		}}
		b, ct := mustBuild(t, p)

		// Parse the content-type to extract boundary.
		_, params, err := mime.ParseMediaType(ct)
		if err != nil {
			t.Fatalf("ParseMediaType: %v", err)
		}
		boundary := params["boundary"]
		if boundary == "" {
			t.Fatal("expected boundary in Content-Type")
		}

		mr := multipart.NewReader(strings.NewReader(string(b)), boundary)
		form, err := mr.ReadForm(1 << 20)
		if err != nil {
			t.Fatalf("ReadForm: %v", err)
		}
		if vals := form.Value["message"]; len(vals) == 0 || vals[0] != "hello" {
			t.Errorf("expected message=hello, got %v", vals)
		}
	})

	t.Run("file upload part", func(t *testing.T) {
		t.Parallel()
		imgData := []byte("\x89PNG\r\n")
		p := body.Multipart{Parts: []body.Part{
			{Name: "file", Filename: "img.png", ContentType: "image/png", Data: imgData},
		}}
		b, ct := mustBuild(t, p)

		_, params, _ := mime.ParseMediaType(ct)
		mr := multipart.NewReader(strings.NewReader(string(b)), params["boundary"])
		part, err := mr.NextPart()
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		if part.FileName() != "img.png" {
			t.Errorf("filename: got %q", part.FileName())
		}
		if part.Header.Get("Content-Type") != "image/png" {
			t.Errorf("part Content-Type: got %q", part.Header.Get("Content-Type"))
		}
	})

	t.Run("file upload defaults content-type to octet-stream", func(t *testing.T) {
		t.Parallel()
		p := body.Multipart{Parts: []body.Part{
			{Name: "bin", Filename: "data.bin", Data: []byte{0x00, 0xff}},
		}}
		b, ct := mustBuild(t, p)

		_, params, _ := mime.ParseMediaType(ct)
		mr := multipart.NewReader(strings.NewReader(string(b)), params["boundary"])
		part, err := mr.NextPart()
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		if part.Header.Get("Content-Type") != "application/octet-stream" {
			t.Errorf("expected application/octet-stream, got %q", part.Header.Get("Content-Type"))
		}
	})

	t.Run("mixed text and file parts", func(t *testing.T) {
		t.Parallel()
		p := body.Multipart{Parts: []body.Part{
			{Name: "title", Data: []byte("My Upload")},
			{Name: "attachment", Filename: "doc.pdf", ContentType: "application/pdf", Data: []byte("PDF content")},
		}}
		b, ct := mustBuild(t, p)

		_, params, _ := mime.ParseMediaType(ct)
		mr := multipart.NewReader(strings.NewReader(string(b)), params["boundary"])
		form, err := mr.ReadForm(1 << 20)
		if err != nil {
			t.Fatalf("ReadForm: %v", err)
		}
		if vals := form.Value["title"]; len(vals) == 0 || vals[0] != "My Upload" {
			t.Errorf("title: got %v", vals)
		}
		if files := form.File["attachment"]; len(files) == 0 {
			t.Error("expected attachment file part")
		}
	})

	t.Run("empty part name returns error", func(t *testing.T) {
		t.Parallel()
		p := body.Multipart{Parts: []body.Part{
			{Name: "", Data: []byte("oops")},
		}}
		_, _, err := p.Build()
		if err == nil {
			t.Fatal("expected error for empty part Name")
		}
	})

	t.Run("empty parts produces valid boundary envelope", func(t *testing.T) {
		t.Parallel()
		p := body.Multipart{Parts: nil}
		b, ct := mustBuild(t, p)
		_, params, err := mime.ParseMediaType(ct)
		if err != nil {
			t.Fatalf("ParseMediaType: %v", err)
		}
		if params["boundary"] == "" {
			t.Error("expected non-empty boundary")
		}
		// Body should be a valid (though empty) multipart document.
		mr := multipart.NewReader(strings.NewReader(string(b)), params["boundary"])
		_, err = mr.NextPart()
		if err == nil {
			t.Error("expected EOF / no parts")
		}
	})
}

// ─── GraphQL ─────────────────────────────────────────────────────────────────

func TestGraphQL_Build(t *testing.T) {
	t.Parallel()

	t.Run("query only", func(t *testing.T) {
		t.Parallel()
		p := body.GraphQL{Query: "{ users { id name } }"}
		b, ct := mustBuild(t, p)
		assertContentType(t, ct, "application/json")

		var payload map[string]any
		if err := json.Unmarshal(b, &payload); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if payload["query"] != "{ users { id name } }" {
			t.Errorf("query field: got %v", payload["query"])
		}
		if _, ok := payload["operationName"]; ok {
			t.Error("operationName should be omitted when empty")
		}
		if _, ok := payload["variables"]; ok {
			t.Error("variables should be omitted when nil")
		}
	})

	t.Run("query with variables", func(t *testing.T) {
		t.Parallel()
		p := body.GraphQL{
			Query:     "query GetUser($id: ID!) { user(id: $id) { name } }",
			Variables: map[string]any{"id": "42"},
		}
		b, _ := mustBuild(t, p)

		var payload map[string]any
		if err := json.Unmarshal(b, &payload); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		vars, _ := payload["variables"].(map[string]any)
		if vars["id"] != "42" {
			t.Errorf("variables.id: got %v", vars["id"])
		}
	})

	t.Run("operation name is included when set", func(t *testing.T) {
		t.Parallel()
		p := body.GraphQL{
			Query:         "query A { a } query B { b }",
			OperationName: "A",
		}
		b, _ := mustBuild(t, p)
		var payload map[string]any
		if err := json.Unmarshal(b, &payload); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if payload["operationName"] != "A" {
			t.Errorf("operationName: got %v", payload["operationName"])
		}
	})

	t.Run("empty query returns error", func(t *testing.T) {
		t.Parallel()
		_, _, err := body.GraphQL{Query: ""}.Build()
		if err == nil {
			t.Fatal("expected error for empty query")
		}
	})

	t.Run("whitespace-only query returns error", func(t *testing.T) {
		t.Parallel()
		_, _, err := body.GraphQL{Query: "   \t\n"}.Build()
		if err == nil {
			t.Fatal("expected error for whitespace-only query")
		}
	})
}

// ─── XML ─────────────────────────────────────────────────────────────────────

type xmlItem struct {
	Name  string `xml:"name"`
	Value int    `xml:"value"`
}

func TestXML_Build(t *testing.T) {
	t.Parallel()

	t.Run("pre-built bytes", func(t *testing.T) {
		t.Parallel()
		raw := []byte(`<root><item>1</item></root>`)
		p := body.XML{Data: raw}
		b, ct := mustBuild(t, p)
		assertContentType(t, ct, "application/xml")
		if string(b) != string(raw) {
			t.Errorf("body: got %q, want %q", b, raw)
		}
	})

	t.Run("struct encoding", func(t *testing.T) {
		t.Parallel()
		p := body.XML{Value: xmlItem{Name: "price", Value: 99}}
		b, ct := mustBuild(t, p)
		assertContentType(t, ct, "application/xml")
		if !strings.Contains(string(b), "<name>price</name>") {
			t.Errorf("expected <name>price</name> in %s", b)
		}
		if !strings.Contains(string(b), "<value>99</value>") {
			t.Errorf("expected <value>99</value> in %s", b)
		}
	})

	t.Run("empty XML produces empty body", func(t *testing.T) {
		t.Parallel()
		p := body.XML{}
		b, ct := mustBuild(t, p)
		assertContentType(t, ct, "application/xml")
		if len(b) != 0 {
			t.Errorf("expected empty body, got %q", b)
		}
	})

	t.Run("both Data and Value returns error", func(t *testing.T) {
		t.Parallel()
		p := body.XML{Data: []byte("<a/>"), Value: xmlItem{}}
		_, _, err := p.Build()
		if err == nil {
			t.Fatal("expected error when both Data and Value are set")
		}
	})
}

// ─── Text ─────────────────────────────────────────────────────────────────────

func TestText_Build(t *testing.T) {
	t.Parallel()

	t.Run("plain text body", func(t *testing.T) {
		t.Parallel()
		p := body.Text{Data: []byte("hello, world")}
		b, ct := mustBuild(t, p)
		if string(b) != "hello, world" {
			t.Errorf("body: got %q", b)
		}
		if ct != "text/plain; charset=utf-8" {
			t.Errorf("content-type: got %q", ct)
		}
	})

	t.Run("nil data produces empty body", func(t *testing.T) {
		t.Parallel()
		p := body.Text{}
		b, ct := mustBuild(t, p)
		if len(b) != 0 {
			t.Errorf("expected empty body, got %q", b)
		}
		if ct != "text/plain; charset=utf-8" {
			t.Errorf("content-type: got %q", ct)
		}
	})

	t.Run("unicode content", func(t *testing.T) {
		t.Parallel()
		p := body.Text{Data: []byte("日本語テスト 🚀")}
		b, _ := mustBuild(t, p)
		if string(b) != "日本語テスト 🚀" {
			t.Errorf("unicode body mismatch: got %q", b)
		}
	})
}

// ─── Interface compliance ─────────────────────────────────────────────────────

// TestProvider_InterfaceCompliance verifies all concrete types satisfy the
// Provider interface at compile time.
func TestProvider_InterfaceCompliance(t *testing.T) {
	t.Parallel()
	providers := []body.Provider{
		body.Raw{},
		body.JSON{Value: nil},
		body.Form{},
		body.Multipart{},
		body.GraphQL{Query: "{ ok }"},
		body.XML{},
		body.Text{},
	}
	for _, p := range providers {
		// Build may error (e.g. Raw with nil); we only care that the method exists.
		_, _, _ = p.Build()
	}
}
