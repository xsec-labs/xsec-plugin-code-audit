package store

import (
	"os"
	"strings"
	"testing"
)

func TestRunIDParsing(t *testing.T) {
	for _, ok := range []string{"repo-1a2b3c4d/run-1", "a.b_c/run-999999"} {
		if _, err := ParseRunID("p", ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "run-1", "../x/run-1", "a/run-0", "a/run-01", "a/run-1/../x", "a/b/run-1", "a/run-1000000", "/run-1", ".a/run-1"} {
		if _, err := ParseRunID("p", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSafeProject(t *testing.T) {
	for _, id := range []string{"../../etc", "a/b", "..", ".", "", "a\\b", strings.Repeat("x", 300), "项目"} {
		got := SafeProject(id)
		if !projectRe.MatchString(got) || got == "." || got == ".." {
			t.Errorf("SafeProject(%q) = %q", id, got)
		}
	}
	if SafeProject("proj-1") != "proj-1" {
		t.Error("a plain id must stay as it is")
	}
	if SafeProject("a/b") == SafeProject("a-b") {
		t.Error("distinct ids collided")
	}
}

func TestNextRunAndRemove(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for want := 1; want <= 3; want++ {
		r, err := s.NextRun("p", "repo")
		if err != nil || r.N != want {
			t.Fatalf("run %d: %v %v", want, r, err)
		}
	}
	if err := s.RemoveRun(RunRef{Project: "p", Repo: "repo", N: 2}); err != nil {
		t.Fatal(err)
	}
	r, _ := s.NextRun("p", "repo")
	if r.N != 4 {
		t.Fatalf("a deleted number is reused: %d", r.N)
	}
	runs, _ := s.ListRuns("p")
	if len(runs) != 3 || runs[0].N != 4 {
		t.Fatalf("list: %v", runs)
	}
	if _, err := s.NextRun("p", "../x"); err == nil {
		t.Fatal("bad repo accepted")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/a/b.json"
	if err := WriteFile(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, []byte("two")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "two" {
		t.Fatalf("%q", b)
	}
	ents, _ := os.ReadDir(dir + "/a")
	if len(ents) != 1 {
		t.Fatalf("temp files left behind: %v", ents)
	}
}
