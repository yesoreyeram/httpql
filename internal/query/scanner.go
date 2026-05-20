package query

import (
	"strings"
	"unicode"
)

// tokKind identifies the kind of a scanned token.
type tokKind uint8

const (
	tokEOF    tokKind = iota
	tokWord           // keyword, identifier, or bare non-URL word
	tokInt            // integer literal
	tokURL            // value containing "://"
	tokJSON           // balanced { … } or [ … ] JSON blob
	tokQStr           // "…" double-quoted string
	tokComma          // ,
	tokLParen         // (
	tokRParen         // )
	tokGTE            // >=
)

type tok struct {
	kind tokKind
	val  string
}

// scanner is a single-pass rune-level tokeniser with one-token look-ahead.
type scanner struct {
	r   []rune
	pos int
	buf *tok // one-token look-ahead buffer
}

func newScanner(src string) *scanner {
	return &scanner{r: []rune(src)}
}

// peek returns the next token without consuming it.
func (s *scanner) peek() tok {
	if s.buf == nil {
		t := s.scan()
		s.buf = &t
	}
	return *s.buf
}

// next returns and consumes the next token.
func (s *scanner) next() tok {
	if s.buf != nil {
		t := *s.buf
		s.buf = nil
		return t
	}
	return s.scan()
}

// scan returns the next token from the raw rune slice.
func (s *scanner) scan() tok {
	s.skipWSAndComments()
	if s.pos >= len(s.r) {
		return tok{kind: tokEOF}
	}
	c := s.r[s.pos]
	switch {
	case c == ',':
		s.pos++
		return tok{kind: tokComma, val: ","}
	case c == '(':
		s.pos++
		return tok{kind: tokLParen, val: "("}
	case c == ')':
		s.pos++
		return tok{kind: tokRParen, val: ")"}
	case c == '>' && s.pos+1 < len(s.r) && s.r[s.pos+1] == '=':
		s.pos += 2
		return tok{kind: tokGTE, val: ">="}
	case c == '{' || c == '[':
		return s.scanJSON()
	case c == '"':
		return s.scanQStr()
	case unicode.IsDigit(c):
		return s.scanInt()
	default:
		return s.scanWord()
	}
}

// skipWSAndComments advances past whitespace and -- line comments.
func (s *scanner) skipWSAndComments() {
	for s.pos < len(s.r) {
		c := s.r[s.pos]
		if unicode.IsSpace(c) {
			s.pos++
			continue
		}
		// -- line comment: skip to end of line
		if c == '-' && s.pos+1 < len(s.r) && s.r[s.pos+1] == '-' {
			for s.pos < len(s.r) && s.r[s.pos] != '\n' {
				s.pos++
			}
			continue
		}
		break
	}
}

func (s *scanner) scanInt() tok {
	start := s.pos
	for s.pos < len(s.r) && unicode.IsDigit(s.r[s.pos]) {
		s.pos++
	}
	return tok{kind: tokInt, val: string(s.r[start:s.pos])}
}

// scanWord reads a contiguous run of non-whitespace, non-special characters.
// If the result contains "://" it is classified as a URL token.
// ${...} interpolation placeholders are treated as part of the word.
func (s *scanner) scanWord() tok {
	start := s.pos
	for s.pos < len(s.r) {
		c := s.r[s.pos]
		// ${...} interpolation blocks are part of the current word/URL.
		if c == '$' && s.pos+1 < len(s.r) && s.r[s.pos+1] == '{' {
			s.pos += 2 // skip '${'
			for s.pos < len(s.r) && s.r[s.pos] != '}' {
				s.pos++
			}
			if s.pos < len(s.r) {
				s.pos++ // skip '}'
			}
			continue
		}
		if unicode.IsSpace(c) || c == ',' || c == '(' || c == ')' ||
			c == '{' || c == '[' || c == '"' {
			break
		}
		s.pos++
	}
	val := string(s.r[start:s.pos])
	if strings.Contains(val, "://") {
		return tok{kind: tokURL, val: val}
	}
	return tok{kind: tokWord, val: val}
}

// scanQStr reads a double-quoted string, handling backslash escapes.
func (s *scanner) scanQStr() tok {
	s.pos++ // skip opening "
	var b strings.Builder
	for s.pos < len(s.r) {
		c := s.r[s.pos]
		if c == '"' {
			s.pos++
			break
		}
		if c == '\\' {
			s.pos++
			if s.pos < len(s.r) {
				b.WriteRune(s.r[s.pos])
				s.pos++
			}
			continue
		}
		b.WriteRune(c)
		s.pos++
	}
	return tok{kind: tokQStr, val: b.String()}
}

// scanJSON reads a balanced JSON value starting with { or [.
// It correctly handles nested objects, arrays, and string literals.
func (s *scanner) scanJSON() tok {
	var b strings.Builder
	depth := 0
	for s.pos < len(s.r) {
		c := s.r[s.pos]
		switch c {
		case '{', '[':
			depth++
			b.WriteRune(c)
			s.pos++
		case '}', ']':
			depth--
			b.WriteRune(c)
			s.pos++
			if depth == 0 {
				return tok{kind: tokJSON, val: b.String()}
			}
		case '"':
			// Consume JSON string, respecting backslash escapes.
			b.WriteRune(c)
			s.pos++
			for s.pos < len(s.r) {
				cc := s.r[s.pos]
				b.WriteRune(cc)
				s.pos++
				if cc == '"' {
					break
				}
				if cc == '\\' && s.pos < len(s.r) {
					b.WriteRune(s.r[s.pos])
					s.pos++
				}
			}
		default:
			b.WriteRune(c)
			s.pos++
		}
	}
	// Unbalanced JSON — return what we have; the parser will error later.
	return tok{kind: tokJSON, val: b.String()}
}

// readLine reads from the current position to the end of the current line
// (stopping at '\n' or EOF) and returns the trimmed text.
// It is used by BODY FORM, BODY TEXT, and BODY RAW to read bare-string values.
// The look-ahead buffer must be nil before calling this method.
func (s *scanner) readLine() string {
	start := s.pos
	for s.pos < len(s.r) && s.r[s.pos] != '\n' {
		s.pos++
	}
	return strings.TrimSpace(string(s.r[start:s.pos]))
}
