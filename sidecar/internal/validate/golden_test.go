package validate

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/jsonv"
)

type goldenCase struct {
	Input  string   `json:"input"`
	Errors []string `json:"errors"`
}

func loadGolden(t *testing.T, name string) []goldenCase {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "..", "testdata", "golden", name+".json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var cases []goldenCase
	if err := json.NewDecoder(zr).Decode(&cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

func runGolden(t *testing.T, name string, run func(*jsonv.Value) []string) {
	cases := loadGolden(t, name)
	if len(cases) < 100 {
		t.Fatalf("golden corpus too small: %d", len(cases))
	}
	failures := 0
	for i, c := range cases {
		doc, err := jsonv.Parse([]byte(c.Input))
		if err != nil {
			t.Fatalf("case %d: parse: %v", i, err)
		}
		got := run(doc)
		want := c.Errors
		if want == nil {
			want = []string{}
		}
		if got == nil {
			got = []string{}
		}
		if !reflect.DeepEqual(got, want) {
			failures++
			if failures <= 8 {
				in := c.Input
				if len(in) > 600 {
					in = in[:600] + "..."
				}
				t.Errorf("case %d differs\ninput: %s\nwant: %q\ngot:  %q", i, in, want, got)
			}
		}
	}
	if failures > 0 {
		t.Fatalf("%d of %d golden cases differ", failures, len(cases))
	}
}

func TestFindingsGolden(t *testing.T) {
	runGolden(t, "findings", func(v *jsonv.Value) []string {
		errs, err := ValidateFindings(v)
		if err != nil {
			t.Fatal(err)
		}
		return errs
	})
}

func TestLedgerGolden(t *testing.T) {
	runGolden(t, "ledger", ValidateLedger)
}
