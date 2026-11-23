package tools

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"

	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/jsonv"
	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/store"
)

// ExecutionPolicy is the value the Cloudflare skill expects in run-metadata.json. This plugin never runs target
// code, which satisfies "sandboxed-source-and-local-only" by running nothing at all.
const ExecutionPolicy = "sandboxed-source-and-local-only"

// Run statuses.
const (
	StatusInProgress = "in_progress"
	StatusComplete   = "complete"
	StatusIncomplete = "incomplete"
)

// SourceRef is the reviewed commit.
type SourceRef struct {
	Commit string `json:"commit,omitempty"`
	Dirty  bool   `json:"dirty"`
}

// Scope is what the run covers.
type Scope struct {
	Mode  string   `json:"mode"` // repo | paths | diff
	Paths []string `json:"paths,omitempty"`
	Base  string   `json:"base,omitempty"`
	Head  string   `json:"head,omitempty"`
}

// Counts summarises a run's findings and ledger for list views.
type Counts struct {
	Confirmed       int            `json:"confirmed"`
	NeedsValidation int            `json:"needs_validation"`
	Rejected        int            `json:"rejected"`
	Severity        map[string]int `json:"severity"`
	Units           int            `json:"units"`
	UnitStatus      map[string]int `json:"unit_status"`
}

// Metadata is run-metadata.json: the fields the skill requires plus xSec's own.
type Metadata struct {
	RunID              string            `json:"run_id"`
	Repo               string            `json:"repo"`
	Target             string            `json:"target"`
	SourceRef          SourceRef         `json:"source_ref"`
	Profile            string            `json:"profile"`
	ScopePaths         []string          `json:"scope_paths"`
	Scope              Scope             `json:"scope"`
	Budget             *int              `json:"budget"`
	ExecutionPolicy    string            `json:"execution_policy"`
	SelectedCompanions []string          `json:"selected_companion_files"`
	PriorRuns          []string          `json:"prior_run_paths"`
	SharedFileOwners   map[string]string `json:"shared_file_owners"`
	RunStatus          string            `json:"run_status"`
	IncompleteReason   string            `json:"incomplete_reason,omitempty"`
	Phase              string            `json:"phase"`
	Focus              []string          `json:"focus"`
	Notes              []string          `json:"notes,omitempty"`
	CreatedAt          string            `json:"created_at"`
	UpdatedAt          string            `json:"updated_at"`
	CompletedAt        string            `json:"completed_at,omitempty"`
	Counts             Counts            `json:"counts"`
}

func (c *Call) loadMeta(ref store.RunRef) (*Metadata, error) {
	raw, err := c.Env.Store.ReadFile(ref, store.FileMetadata)
	if err != nil {
		return nil, errf("run %s has no metadata: %v", ref.ID(), err)
	}
	var m Metadata
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, errf("run %s metadata is damaged: %v", ref.ID(), err)
	}
	return &m, nil
}

func (c *Call) saveMeta(ref store.RunRef, m *Metadata) error {
	m.UpdatedAt = c.now()
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return c.Env.Store.WriteRunFile(ref, store.FileMetadata, append(raw, '\n'))
}

// ---- agents.json ----

// AgentEvent is one dispatch bookkeeping entry.
type AgentEvent struct {
	At      string   `json:"at"`
	Event   string   `json:"event"` // dispatched | returned | failed
	AgentID string   `json:"agent_id"`
	Role    string   `json:"role"`
	Phase   string   `json:"phase,omitempty"`
	UnitIDs []string `json:"unit_ids,omitempty"`
	Summary string   `json:"summary,omitempty"`
}

// Agents is agents.json.
type Agents struct {
	Events []AgentEvent `json:"events"`
}

func (a *Agents) dispatched() int {
	n := 0
	for _, e := range a.Events {
		if e.Event == "dispatched" {
			n++
		}
	}
	return n
}

// Running returns agents dispatched and not yet returned or failed.
func (a *Agents) Running() []AgentEvent {
	state := map[string]AgentEvent{}
	var order []string
	for _, e := range a.Events {
		switch e.Event {
		case "dispatched":
			if _, ok := state[e.AgentID]; !ok {
				order = append(order, e.AgentID)
			}
			state[e.AgentID] = e
		case "returned", "failed":
			delete(state, e.AgentID)
		}
	}
	var out []AgentEvent
	for _, id := range order {
		if e, ok := state[id]; ok {
			out = append(out, e)
		}
	}
	return out
}

func (c *Call) loadAgents(ref store.RunRef) (*Agents, error) {
	raw, err := c.Env.Store.ReadFile(ref, store.FileAgents)
	if errors.Is(err, os.ErrNotExist) {
		return &Agents{Events: []AgentEvent{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var a Agents
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, errf("agents.json is damaged: %v", err)
	}
	return &a, nil
}

func (c *Call) saveAgents(ref store.RunRef, a *Agents) error {
	raw, _ := json.MarshalIndent(a, "", "  ")
	return c.Env.Store.WriteRunFile(ref, store.FileAgents, append(raw, '\n'))
}

// ---- findings.ext.json ----

// Snippet is source text frozen at the moment a finding was stored.
type Snippet struct {
	StartLine int      `json:"start_line"`
	Lines     []string `json:"lines"`
	Truncated bool     `json:"truncated,omitempty"`
}

// ExtStep is the xSec extension of one trace/evidence entry.
type ExtStep struct {
	Role    string  `json:"role"` // trace | evidence
	Index   int     `json:"index"`
	Kind    string  `json:"kind,omitempty"`
	File    string  `json:"file"`
	Line    int     `json:"line"`
	SHA256  string  `json:"file_sha256,omitempty"`
	Snippet Snippet `json:"snippet"`
}

// ExtFinding is findings.ext.json for one fingerprint.
type ExtFinding struct {
	Steps []ExtStep `json:"steps"`
	CWE   []string  `json:"cwe,omitempty"`
	Tags  []string  `json:"tags,omitempty"`
	Notes string    `json:"notes,omitempty"`
}

// Ext is findings.ext.json.
type Ext struct {
	Findings map[string]*ExtFinding `json:"findings"`
}

func (c *Call) loadExt(ref store.RunRef) (*Ext, error) {
	raw, err := c.Env.Store.ReadFile(ref, store.FileExt)
	if errors.Is(err, os.ErrNotExist) {
		return &Ext{Findings: map[string]*ExtFinding{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var e Ext
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, errf("findings.ext.json is damaged: %v", err)
	}
	if e.Findings == nil {
		e.Findings = map[string]*ExtFinding{}
	}
	return &e, nil
}

// ---- project state ----

// FindingState outlives runs: it is keyed by "<repo>:<fingerprint>".
type FindingState struct {
	Repo         string `json:"repo"`
	Fingerprint  string `json:"fingerprint"`
	FixStatus    string `json:"fix_status,omitempty"` // proposed | fixed | still_present | cannot_determine
	FixNote      string `json:"fix_note,omitempty"`
	FixRun       string `json:"fix_checked_in_run,omitempty"`
	UserDecision string `json:"user_decision,omitempty"` // confirmed_by_user | excluded_by_user
	UserNote     string `json:"user_note,omitempty"`
	VulnID       string `json:"vuln_id,omitempty"`
	FirstSeenRun string `json:"first_seen_run,omitempty"`
	LastSeenRun  string `json:"last_seen_run,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
}

// State is projects/<project>/state.json.
type State struct {
	Findings map[string]*FindingState `json:"findings"`
}

func stateKey(repo, fingerprint string) string { return repo + ":" + fingerprint }

func (c *Call) loadState() (*State, error) {
	raw, err := os.ReadFile(c.Env.Store.StatePath(c.Identity.ProjectID))
	if errors.Is(err, os.ErrNotExist) {
		return &State{Findings: map[string]*FindingState{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, errf("project state is damaged: %v", err)
	}
	if s.Findings == nil {
		s.Findings = map[string]*FindingState{}
	}
	return &s, nil
}

func (c *Call) saveState(s *State) error {
	raw, _ := json.MarshalIndent(s, "", "  ")
	return store.WriteFile(c.Env.Store.StatePath(c.Identity.ProjectID), append(raw, '\n'))
}

// ---- documents ----

func (c *Call) readDoc(ref store.RunRef, name string) (*jsonv.Value, error) {
	raw, err := c.Env.Store.ReadFile(ref, name)
	if err != nil {
		return nil, err
	}
	return jsonv.Parse(raw)
}

func writeDoc(c *Call, ref store.RunRef, name string, v *jsonv.Value) error {
	return c.Env.Store.WriteRunFile(ref, name, append(jsonv.Marshal(v, "  "), '\n'))
}

// sortStrings sorts by UTF-16 order like the validators expect.
func sortByUTF16(keys []string, less func(a, b string) bool) {
	sort.SliceStable(keys, func(i, j int) bool { return less(keys[i], keys[j]) })
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}
