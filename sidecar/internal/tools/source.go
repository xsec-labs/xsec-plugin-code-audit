package tools

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	maxSourceBytes  = 16 << 20
	snippetContext  = 3
	snippetLineRune = 300
)

// sourceFile is one audited file as it was when a finding was stored.
type sourceFile struct {
	lines  []string
	sha256 string
}

// sourceReader resolves repository-relative paths inside the audit target. It only reads: a symlink that leaves
// the target is refused, and nothing is ever executed.
type sourceReader struct {
	root  string
	cache map[string]*sourceFile
	fail  map[string]string
}

func newSourceReader(target string) (*sourceReader, error) {
	root, err := filepath.EvalSymlinks(target)
	if err != nil {
		return nil, err
	}
	return &sourceReader{root: root, cache: map[string]*sourceFile{}, fail: map[string]string{}}, nil
}

func (r *sourceReader) open(rel string) (*sourceFile, string) {
	if f, ok := r.cache[rel]; ok {
		return f, ""
	}
	if why, ok := r.fail[rel]; ok {
		return nil, why
	}
	f, why := r.read(rel)
	if f == nil {
		r.fail[rel] = why
	} else {
		r.cache[rel] = f
	}
	return f, why
}

func (r *sourceReader) read(rel string) (*sourceFile, string) {
	full := filepath.Join(r.root, filepath.FromSlash(rel))
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, "file does not exist in the audited source"
	}
	if relp, err := filepath.Rel(r.root, real); err != nil || relp == ".." || strings.HasPrefix(relp, ".."+string(filepath.Separator)) {
		return nil, "path resolves outside the audited source"
	}
	st, err := os.Stat(real)
	if err != nil || !st.Mode().IsRegular() {
		return nil, "not a regular file"
	}
	if st.Size() > maxSourceBytes {
		return nil, fmt.Sprintf("file is larger than %d MiB", maxSourceBytes>>20)
	}
	raw, err := os.ReadFile(real)
	if err != nil {
		return nil, "cannot be read: " + err.Error()
	}
	sum := sha256.Sum256(raw)
	text := strings.ToValidUTF8(string(raw), "�")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	var lines []string
	if len(text) > 0 {
		lines = strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	}
	if bytes.IndexByte(raw, 0) >= 0 {
		return nil, "binary file; only text source can be cited"
	}
	return &sourceFile{lines: lines, sha256: hex.EncodeToString(sum[:])}, ""
}

// snippet returns the lines around line (1-based) or an error text when the line does not exist.
func (f *sourceFile) snippet(line int) (Snippet, string) {
	if line < 1 || line > len(f.lines) {
		return Snippet{}, fmt.Sprintf("line %d is outside the file (%d lines)", line, len(f.lines))
	}
	start, end := line-snippetContext, line+snippetContext
	if start < 1 {
		start = 1
	}
	if end > len(f.lines) {
		end = len(f.lines)
	}
	s := Snippet{StartLine: start}
	for _, l := range f.lines[start-1 : end] {
		if utf8.RuneCountInString(l) > snippetLineRune {
			l = string([]rune(l)[:snippetLineRune])
			s.Truncated = true
		}
		s.Lines = append(s.Lines, l)
	}
	return s, ""
}
