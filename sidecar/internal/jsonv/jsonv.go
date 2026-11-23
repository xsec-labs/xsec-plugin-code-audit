// Package jsonv is an order-preserving JSON tree that behaves like JavaScript's JSON.parse for the cases the
// audit validators care about: object keys keep insertion order (a duplicate key keeps its first position and
// its last value), numbers are float64, and a lone UTF-16 surrogate written as an escape survives as WTF-8 so a
// validator can reject it the way the upstream Node validators do.
package jsonv

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Kind is the JSON type of a Value.
type Kind int

const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

// Value is one JSON value.
type Value struct {
	Kind Kind
	B    bool
	N    float64
	S    string // WTF-8: a lone surrogate is kept as its 3-byte form
	A    []*Value
	Keys []string // Object: insertion order
	M    map[string]*Value
}

// TypeName is the JavaScript typeof-style name the upstream messages use.
func (v *Value) TypeName() string {
	switch v.Kind {
	case Null:
		return "null"
	case Bool:
		return "boolean"
	case Number:
		return "number"
	case String:
		return "string"
	case Array:
		return "array"
	}
	return "object"
}

// Has reports whether an object has the key.
func (v *Value) Has(key string) bool {
	if v == nil || v.Kind != Object {
		return false
	}
	_, ok := v.M[key]
	return ok
}

// Get returns the member of an object, or nil.
func (v *Value) Get(key string) *Value {
	if v == nil || v.Kind != Object {
		return nil
	}
	return v.M[key]
}

var absent = &Value{Kind: Null}

// Field is Get for readers that chain lookups: a missing member (or a non-object) yields a shared read-only
// null, so v.Field("a").Field("b").S is "" instead of a nil dereference. Never modify the result.
func (v *Value) Field(key string) *Value {
	if m := v.Get(key); m != nil {
		return m
	}
	return absent
}

// IsObject reports whether v is a non-null, non-array object.
func (v *Value) IsObject() bool { return v != nil && v.Kind == Object }

// IsArray reports whether v is an array.
func (v *Value) IsArray() bool { return v != nil && v.Kind == Array }

// IsString reports whether v is a string.
func (v *Value) IsString() bool { return v != nil && v.Kind == String }

// IsInteger mirrors Number.isInteger.
func (v *Value) IsInteger() bool {
	return v != nil && v.Kind == Number && !math.IsInf(v.N, 0) && !math.IsNaN(v.N) && v.N == math.Trunc(v.N)
}

// Set adds or replaces an object member, keeping the first position of an existing key.
func (v *Value) Set(key string, val *Value) {
	if v.M == nil {
		v.M = map[string]*Value{}
	}
	if _, ok := v.M[key]; !ok {
		v.Keys = append(v.Keys, key)
	}
	v.M[key] = val
}

// Delete removes an object member.
func (v *Value) Delete(key string) {
	if _, ok := v.M[key]; !ok {
		return
	}
	delete(v.M, key)
	for i, k := range v.Keys {
		if k == key {
			v.Keys = append(v.Keys[:i:i], v.Keys[i+1:]...)
			break
		}
	}
}

// Constructors.
func NewObject() *Value               { return &Value{Kind: Object, M: map[string]*Value{}} }
func NewArray(items ...*Value) *Value { return &Value{Kind: Array, A: items} }
func Str(s string) *Value             { return &Value{Kind: String, S: s} }
func Num(n float64) *Value            { return &Value{Kind: Number, N: n} }
func Boolean(b bool) *Value           { return &Value{Kind: Bool, B: b} }
func NullValue() *Value               { return &Value{Kind: Null} }

// Limits guard against hostile input.
const (
	MaxDepth  = 512
	maxValues = 5_000_000
)

type parser struct {
	s      string
	i      int
	values int
}

// Parse decodes one JSON document. Trailing non-space content is an error.
func Parse(data []byte) (*Value, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("input is not valid UTF-8")
	}
	p := &parser{s: string(data)}
	p.skipWS()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.i != len(p.s) {
		return nil, p.errf("unexpected data after the JSON value")
	}
	return v, nil
}

func (p *parser) errf(format string, a ...any) error {
	return fmt.Errorf("invalid JSON at byte %d: %s", p.i, fmt.Sprintf(format, a...))
}

func (p *parser) skipWS() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\r', '\n':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (*Value, error) {
	if depth > MaxDepth {
		return nil, p.errf("nesting is too deep")
	}
	p.values++
	if p.values > maxValues {
		return nil, p.errf("too many values")
	}
	if p.i >= len(p.s) {
		return nil, p.errf("unexpected end of input")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return &Value{Kind: String, S: s}, nil
	case c == 't':
		return p.lit("true", &Value{Kind: Bool, B: true})
	case c == 'f':
		return p.lit("false", &Value{Kind: Bool})
	case c == 'n':
		return p.lit("null", &Value{Kind: Null})
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	return nil, p.errf("unexpected character %q", p.s[p.i])
}

func (p *parser) lit(word string, v *Value) (*Value, error) {
	if !strings.HasPrefix(p.s[p.i:], word) {
		return nil, p.errf("unexpected token")
	}
	p.i += len(word)
	return v, nil
}

func (p *parser) number() (*Value, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	if p.i >= len(p.s) {
		return nil, p.errf("bad number")
	}
	if p.s[p.i] == '0' {
		p.i++
	} else if p.s[p.i] >= '1' && p.s[p.i] <= '9' {
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
	} else {
		return nil, p.errf("bad number")
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		p.i++
		d := p.i
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
		if p.i == d {
			return nil, p.errf("bad number")
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		d := p.i
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
		if p.i == d {
			return nil, p.errf("bad number")
		}
	}
	f, err := strconv.ParseFloat(p.s[start:p.i], 64)
	if err != nil {
		var ne *strconv.NumError
		if errors.As(err, &ne) && errors.Is(ne.Err, strconv.ErrRange) {
			err = nil // ±Inf like JavaScript
		}
	}
	if err != nil {
		return nil, p.errf("bad number")
	}
	return &Value{Kind: Number, N: f}, nil
}

func (p *parser) str() (string, error) {
	p.i++ // opening quote
	var b strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", p.errf("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c < 0x20:
			return "", p.errf("control character in string")
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				return "", p.errf("unterminated escape")
			}
			e := p.s[p.i]
			p.i++
			switch e {
			case '"', '\\', '/':
				b.WriteByte(e)
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				r, err := p.hex4()
				if err != nil {
					return "", err
				}
				if r >= 0xD800 && r <= 0xDBFF && strings.HasPrefix(p.s[p.i:], `\u`) {
					save := p.i
					p.i += 2
					r2, err := p.hex4()
					if err == nil && r2 >= 0xDC00 && r2 <= 0xDFFF {
						b.WriteRune(rune(0x10000 + (r-0xD800)<<10 + (r2 - 0xDC00)))
						continue
					}
					p.i = save
				}
				writeUTF16Unit(&b, r)
			default:
				return "", p.errf("bad escape")
			}
		default:
			b.WriteByte(c)
			p.i++
		}
	}
}

func (p *parser) hex4() (rune, error) {
	if p.i+4 > len(p.s) {
		return 0, p.errf("bad unicode escape")
	}
	n, err := strconv.ParseUint(p.s[p.i:p.i+4], 16, 32)
	if err != nil {
		return 0, p.errf("bad unicode escape")
	}
	p.i += 4
	return rune(n), nil
}

// writeUTF16Unit writes one UTF-16 code unit; a lone surrogate becomes its 3-byte WTF-8 form.
func writeUTF16Unit(b *strings.Builder, r rune) {
	if r >= 0xD800 && r <= 0xDFFF {
		b.WriteByte(0xE0 | byte(r>>12))
		b.WriteByte(0x80 | byte((r>>6)&0x3F))
		b.WriteByte(0x80 | byte(r&0x3F))
		return
	}
	b.WriteRune(r)
}

func (p *parser) array(depth int) (*Value, error) {
	p.i++
	v := &Value{Kind: Array, A: []*Value{}}
	p.skipWS()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return v, nil
	}
	for {
		p.skipWS()
		item, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		v.A = append(v.A, item)
		p.skipWS()
		if p.i >= len(p.s) {
			return nil, p.errf("unterminated array")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == ']' {
			p.i++
			return v, nil
		}
		return nil, p.errf("expected , or ]")
	}
}

func (p *parser) object(depth int) (*Value, error) {
	p.i++
	v := &Value{Kind: Object, M: map[string]*Value{}}
	p.skipWS()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return v, nil
	}
	for {
		p.skipWS()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, p.errf("expected a string key")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		p.skipWS()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, p.errf("expected :")
		}
		p.i++
		p.skipWS()
		item, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		v.Set(k, item)
		p.skipWS()
		if p.i >= len(p.s) {
			return nil, p.errf("unterminated object")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == '}' {
			p.i++
			return v, nil
		}
		return nil, p.errf("expected , or }")
	}
}

// UTF16Len is JavaScript's String.length for a WTF-8 string.
func UTF16Len(s string) int {
	n := 0
	for i := 0; i < len(s); {
		r, size := decodeWTF8(s[i:])
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
		i += size
	}
	return n
}

// CodePointLen counts code points; a lone surrogate counts as one.
func CodePointLen(s string) int {
	n := 0
	for i := 0; i < len(s); {
		_, size := decodeWTF8(s[i:])
		n++
		i += size
	}
	return n
}

// HasLoneSurrogate reports whether s holds a lone UTF-16 surrogate.
func HasLoneSurrogate(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
			return true
		}
	}
	return false
}

// decodeWTF8 decodes one code point, reading a surrogate's 3-byte form as the surrogate itself.
func decodeWTF8(s string) (rune, int) {
	if len(s) >= 3 && s[0] == 0xED && s[1] >= 0xA0 && s[1] <= 0xBF && s[2]&0xC0 == 0x80 {
		return rune(0xD000) | rune(s[1]&0x3F)<<6 | rune(s[2]&0x3F), 3
	}
	r, size := utf8.DecodeRuneInString(s)
	return r, size
}

// Runes iterates the code points of a WTF-8 string.
func Runes(s string) []rune {
	out := make([]rune, 0, len(s))
	for i := 0; i < len(s); {
		r, size := decodeWTF8(s[i:])
		out = append(out, r)
		i += size
	}
	return out
}

// JSNumber formats a float64 the way JavaScript's String(number) does.
func JSNumber(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		return "0"
	}
	abs := math.Abs(f)
	if abs >= 1e21 || abs < 1e-6 {
		s := strconv.FormatFloat(f, 'e', -1, 64)
		mant, exp, _ := strings.Cut(s, "e")
		sign := exp[0]
		exp = strings.TrimLeft(exp[1:], "0")
		return mant + "e" + string(sign) + exp
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// Marshal writes the value as JSON. indent "" gives compact output.
func Marshal(v *Value, indent string) []byte {
	var b strings.Builder
	writeValue(&b, v, indent, 0)
	return []byte(b.String())
}

func writeValue(b *strings.Builder, v *Value, indent string, level int) {
	nl := func(l int) {
		if indent != "" {
			b.WriteByte('\n')
			for i := 0; i < l; i++ {
				b.WriteString(indent)
			}
		}
	}
	switch v.Kind {
	case Null:
		b.WriteString("null")
	case Bool:
		b.WriteString(strconv.FormatBool(v.B))
	case Number:
		if math.IsInf(v.N, 0) || math.IsNaN(v.N) {
			b.WriteString("null")
		} else {
			b.WriteString(JSNumber(v.N))
		}
	case String:
		writeString(b, v.S)
	case Array:
		if len(v.A) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteByte('[')
		for i, it := range v.A {
			if i > 0 {
				b.WriteByte(',')
			}
			nl(level + 1)
			writeValue(b, it, indent, level+1)
		}
		nl(level)
		b.WriteByte(']')
	case Object:
		if len(v.Keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteByte('{')
		for i, k := range v.Keys {
			if i > 0 {
				b.WriteByte(',')
			}
			nl(level + 1)
			writeString(b, k)
			b.WriteByte(':')
			if indent != "" {
				b.WriteByte(' ')
			}
			writeValue(b, v.M[k], indent, level+1)
		}
		nl(level)
		b.WriteByte('}')
	}
}

func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := decodeWTF8(s[i:])
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || (r >= 0xD800 && r <= 0xDFFF) || r == 0x2028 || r == 0x2029:
			fmt.Fprintf(b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	b.WriteByte('"')
}

// Canonical is a deterministic key for a value, used for uniqueness checks like the upstream canonicalKey.
// It returns the key and the byte count the upstream limit measures.
func Canonical(v *Value, limit int) (string, int, error) {
	var b strings.Builder
	bytes := 0
	appendChunk := func(s string) error {
		bytes += len(s)
		if bytes > limit {
			return fmt.Errorf("canonical key exceeds %d byte limit", limit)
		}
		b.WriteString(s)
		return nil
	}
	var enc func(*Value) error
	enc = func(x *Value) error {
		switch x.Kind {
		case Null:
			return appendChunk("null")
		case String:
			var sb strings.Builder
			writeString(&sb, x.S)
			return appendChunk("string:" + sb.String())
		case Number:
			n := x.N
			if n == 0 {
				return appendChunk("number:0")
			}
			return appendChunk("number:" + JSNumber(n))
		case Bool:
			return appendChunk("boolean:" + strconv.FormatBool(x.B))
		case Array:
			if err := appendChunk("array:["); err != nil {
				return err
			}
			for i, e := range x.A {
				if i > 0 {
					if err := appendChunk(","); err != nil {
						return err
					}
				}
				if err := enc(e); err != nil {
					return err
				}
			}
			return appendChunk("]")
		}
		if err := appendChunk("object:{"); err != nil {
			return err
		}
		keys := append([]string(nil), x.Keys...)
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				if err := appendChunk(","); err != nil {
					return err
				}
			}
			var sb strings.Builder
			writeString(&sb, k)
			if err := appendChunk(sb.String()); err != nil {
				return err
			}
			if err := appendChunk(":"); err != nil {
				return err
			}
			if err := enc(x.M[k]); err != nil {
				return err
			}
		}
		return appendChunk("}")
	}
	if err := enc(v); err != nil {
		return "", bytes, err
	}
	return b.String(), bytes, nil
}

// DeepEqual mirrors the upstream deepEqual.
func DeepEqual(a, b *Value) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil || a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case Null:
		return true
	case Bool:
		return a.B == b.B
	case Number:
		return a.N == b.N
	case String:
		return a.S == b.S
	case Array:
		if len(a.A) != len(b.A) {
			return false
		}
		for i := range a.A {
			if !DeepEqual(a.A[i], b.A[i]) {
				return false
			}
		}
		return true
	}
	if len(a.Keys) != len(b.Keys) {
		return false
	}
	for _, k := range a.Keys {
		o, ok := b.M[k]
		if !ok || !DeepEqual(a.M[k], o) {
			return false
		}
	}
	return true
}
