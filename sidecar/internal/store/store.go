// Package store keeps audit runs on disk under PLUGIN_DATA. Layout:
//
//	runs/<project>/<repo>/run-<N>/   run-metadata.json architecture.md coverage-ledger.json findings.json
//	                                  findings.ext.json agents.json REPORT.md FINDINGS-DETAIL.md NEEDS-VALIDATION.md exports/
//	projects/<project>/state.json    per-finding state that outlives runs (fix status, user decision, vuln link)
//
// The file names of the first group match the Cloudflare skill's run directory so a run folder is readable by
// anyone who knows that format. Everything xSec adds lives in findings.ext.json, agents.json and state.json.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// File names inside a run directory.
const (
	FileMetadata     = "run-metadata.json"
	FileArchitecture = "architecture.md"
	FileLedger       = "coverage-ledger.json"
	FileFindings     = "findings.json"
	FileExt          = "findings.ext.json"
	FileAgents       = "agents.json"
	FileReport       = "REPORT.md"
	FileDetail       = "FINDINGS-DETAIL.md"
	FileNeeds        = "NEEDS-VALIDATION.md"
	DirExports       = "exports"
)

// Store is the on-disk run store. One process owns a data directory; a mutex serializes writers.
type Store struct {
	root string
	mu   sync.Mutex
}

// Open creates the store under dataDir.
func Open(dataDir string) (*Store, error) {
	if dataDir == "" {
		return nil, errors.New("data directory is empty")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(abs, "runs"), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(abs, "projects"), 0o700); err != nil {
		return nil, err
	}
	return &Store{root: abs}, nil
}

// Root is the data directory.
func (s *Store) Root() string { return s.root }

// Lock serializes a read-modify-write sequence.
func (s *Store) Lock()   { s.mu.Lock() }
func (s *Store) Unlock() { s.mu.Unlock() }

var (
	projectRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	repoRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
	runRe     = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]{0,95})/run-([1-9][0-9]{0,5})$`)
)

// SafeProject turns any project identifier into a directory-safe segment.
func SafeProject(id string) string {
	if projectRe.MatchString(id) && id != "." && id != ".." {
		return id
	}
	sum := make([]byte, 6)
	for i, b := range []byte(id) {
		sum[i%6] ^= b
	}
	clean := regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(id, "-")
	clean = strings.Trim(clean, "-._")
	if len(clean) > 40 {
		clean = clean[:40]
	}
	if clean == "" {
		clean = "p"
	}
	return clean + "-" + hex.EncodeToString(sum)
}

// RunRef names one run.
type RunRef struct {
	Project string
	Repo    string
	N       int
}

// ID is the public run id, "<repo>/run-<N>".
func (r RunRef) ID() string { return fmt.Sprintf("%s/run-%d", r.Repo, r.N) }

// ParseRunID reads a public run id for a project.
func ParseRunID(project, id string) (RunRef, error) {
	m := runRe.FindStringSubmatch(id)
	if m == nil {
		return RunRef{}, fmt.Errorf("invalid run_id %q (expected <repo>/run-<N>)", id)
	}
	n, _ := strconv.Atoi(m[2])
	return RunRef{Project: SafeProject(project), Repo: m[1], N: n}, nil
}

// RepoSlug derives a stable directory name for a target path: base name plus a short hash of the full path.
func RepoSlug(target string) string {
	base := filepath.Base(filepath.Clean(target))
	base = regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(base, "-")
	base = strings.Trim(base, "-._")
	if base == "" {
		base = "repo"
	}
	if len(base) > 60 {
		base = base[:60]
	}
	h := fnv64(target)
	return fmt.Sprintf("%s-%08x", base, uint32(h))
}

func fnv64(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// Dir is the run directory.
func (s *Store) Dir(r RunRef) string {
	return filepath.Join(s.root, "runs", r.Project, r.Repo, "run-"+strconv.Itoa(r.N))
}

// Path joins a file name to the run directory.
func (s *Store) Path(r RunRef, name string) string { return filepath.Join(s.Dir(r), name) }

// Exists reports whether the run directory exists.
func (s *Store) Exists(r RunRef) bool {
	st, err := os.Stat(s.Dir(r))
	return err == nil && st.IsDir()
}

// NextRun allocates the next run number for the repo and creates its directory.
func (s *Store) NextRun(project, repo string) (RunRef, error) {
	if !repoRe.MatchString(repo) {
		return RunRef{}, fmt.Errorf("invalid repo name %q", repo)
	}
	p := SafeProject(project)
	parent := filepath.Join(s.root, "runs", p, repo)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return RunRef{}, err
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		return RunRef{}, err
	}
	max := 0
	for _, e := range entries {
		if n, ok := strings.CutPrefix(e.Name(), "run-"); ok {
			if v, err := strconv.Atoi(n); err == nil && v > max {
				max = v
			}
		}
	}
	ref := RunRef{Project: p, Repo: repo, N: max + 1}
	if err := os.Mkdir(s.Dir(ref), 0o700); err != nil {
		return RunRef{}, err
	}
	return ref, nil
}

// ListRuns lists every run of a project, newest directory first within each repo.
func (s *Store) ListRuns(project string) ([]RunRef, error) {
	p := SafeProject(project)
	base := filepath.Join(s.root, "runs", p)
	repos, err := os.ReadDir(base)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []RunRef
	for _, repo := range repos {
		if !repo.IsDir() || !repoRe.MatchString(repo.Name()) {
			continue
		}
		runs, err := os.ReadDir(filepath.Join(base, repo.Name()))
		if err != nil {
			continue
		}
		for _, run := range runs {
			n, ok := strings.CutPrefix(run.Name(), "run-")
			if !ok || !run.IsDir() {
				continue
			}
			v, err := strconv.Atoi(n)
			if err != nil || v < 1 {
				continue
			}
			out = append(out, RunRef{Project: p, Repo: repo.Name(), N: v})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Repo != out[j].Repo {
			return out[i].Repo < out[j].Repo
		}
		return out[i].N > out[j].N
	})
	return out, nil
}

// RemoveRun deletes a run directory.
func (s *Store) RemoveRun(r RunRef) error {
	if !s.Exists(r) {
		return os.ErrNotExist
	}
	return os.RemoveAll(s.Dir(r))
}

// WriteFile writes data atomically (temp file in the same directory, then rename).
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var tag [4]byte
	_, _ = rand.Read(tag[:])
	tmp := filepath.Join(dir, "."+filepath.Base(path)+"."+hex.EncodeToString(tag[:])+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ReadFile reads a run file; a missing file returns os.ErrNotExist.
func (s *Store) ReadFile(r RunRef, name string) ([]byte, error) {
	return os.ReadFile(s.Path(r, name))
}

// WriteRunFile writes one file of a run.
func (s *Store) WriteRunFile(r RunRef, name string, data []byte) error {
	return WriteFile(s.Path(r, name), data)
}

// StatePath is the project-level finding state file.
func (s *Store) StatePath(project string) string {
	return filepath.Join(s.root, "projects", SafeProject(project), "state.json")
}
