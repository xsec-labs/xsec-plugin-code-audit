package validate

import (
	"fmt"
	"strings"

	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/jsonv"
)

// Coverage-ledger limits, same as the upstream LIMITS.
const (
	ledgerMaxUnits       = 10000
	ledgerMaxListItems   = 1000
	ledgerObjectFields   = 1000
	ledgerNestingDepth   = 64
	ledgerPreflightValue = 500000
	maxTextLength        = 4096
)

var ledgerRequiredFields = []string{
	"coverage_id", "canonical_refs", "surface", "boundary", "subsystem", "attack_class", "starting_paths",
	"ordinary_attack_class_block", "selected_companion_blocks", "excluded_blocks", "prior_status", "attempts",
	"wave", "status", "agent_id", "reviewed_paths", "local_checks", "result_fingerprints", "unresolved",
}

var refFields = []string{"surface", "boundary", "subsystem", "attack_class"}

var ledgerStatuses = set("planned", "not_applicable", "out_of_scope", "in_progress", "covered", "candidate", "blocked", "deferred")
var attemptStatuses = set("covered", "candidate", "blocked")
var attemptFields = []string{"wave", "status", "agent_id", "reviewed_paths", "local_checks", "result_fingerprints", "unresolved", "reassignment_reason"}
var priorStatuses = set("new", "prior_confirmed_same_source", "prior_confirmed_changed_source", "prior_needs_validation",
	"prior_deferred", "prior_blocked", "prior_out_of_scope", "prior_covered_same_source", "prior_covered_changed_source",
	"prior_rejected_claim_changed", "none")

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

func isNullV(v *jsonv.Value) bool { return v != nil && v.Kind == jsonv.Null }

func isVisibleText(v *jsonv.Value, maxLength int) bool {
	return v.IsString() && v.S != "" && jsonv.UTF16Len(v.S) <= maxLength && jsTrim(v.S) == v.S && HasVisibleProse(v.S)
}

func isCanonicalRef(v *jsonv.Value) bool {
	if !isVisibleText(v, 1024) {
		return false
	}
	for _, r := range jsonv.Runes(v.S) {
		if pathForbidden(r) {
			return false
		}
	}
	return isNFC(v.S)
}

func encodeCanonicalRef(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// CanonicalCoverageID derives the coverage ID from canonical_refs; ok is false when the refs are malformed.
func CanonicalCoverageID(refs *jsonv.Value) (string, bool) {
	if !refs.IsObject() {
		return "", false
	}
	fields := refFields
	if refs.Has("lifecycle") {
		fields = append(append([]string(nil), refFields...), "lifecycle")
	}
	if len(refs.Keys) != len(fields) {
		return "", false
	}
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		v := refs.Get(f)
		if v == nil || !isCanonicalRef(v) {
			return "", false
		}
		parts = append(parts, encodeCanonicalRef(v.S))
	}
	return strings.Join(parts, "::"), true
}

func isOwnedArtifactPath(v, agentID *jsonv.Value) bool {
	if !IsSafeAgentID(agentID) || !IsSafeRelativeSourcePath(v) {
		return false
	}
	prefix := "agents/" + agentID.S + "/artifacts/"
	return strings.HasPrefix(v.S, prefix) && jsonv.UTF16Len(v.S) > jsonv.UTF16Len(prefix)
}

type strArrayOpts struct{ allowEmpty, fingerprint, pathValue bool }

func validateStringArray(v *jsonv.Value, location string, errs *errList, o strArrayOpts) {
	if !v.IsArray() {
		errs.push(location + ": expected array")
		return
	}
	if !o.allowEmpty && len(v.A) == 0 {
		errs.push(location + ": must not be empty")
	}
	if len(v.A) > ledgerMaxListItems {
		errs.push(fmt.Sprintf("%s: exceeds %d entries", location, ledgerMaxListItems))
	}
	seen := map[string]bool{}
	for i, entry := range v.A {
		if i >= ledgerMaxListItems {
			break
		}
		loc := fmt.Sprintf("%s[%d]", location, i)
		var ok bool
		if o.pathValue {
			ok = IsSafeRelativeSourcePath(entry)
		} else {
			ok = isVisibleText(entry, maxTextLength)
		}
		if !ok {
			kind := "text"
			if o.pathValue {
				kind = "repository-relative path"
			}
			errs.push(fmt.Sprintf("%s: invalid %s", loc, kind))
		}
		if o.fingerprint && entry.IsString() && !fingerprintPattern.MatchString(entry.S) {
			errs.push(loc + ": invalid fingerprint")
		}
		if entry.IsString() {
			if seen[entry.S] {
				errs.push(loc + ": duplicate entry")
			}
			seen[entry.S] = true
		}
	}
}

func validateChecks(v *jsonv.Value, location string, errs *errList) {
	if !v.IsArray() {
		errs.push(location + ": expected array")
		return
	}
	if len(v.A) > ledgerMaxListItems {
		errs.push(fmt.Sprintf("%s: exceeds %d entries", location, ledgerMaxListItems))
	}
	for i, check := range v.A {
		if i >= ledgerMaxListItems {
			break
		}
		base := fmt.Sprintf("%s[%d]", location, i)
		if !check.IsObject() {
			errs.push(base + ": expected object")
			continue
		}
		for _, f := range []string{"agent_id", "reviewed_paths", "invariant", "method", "result", "artifact"} {
			if !check.Has(f) {
				errs.push(fmt.Sprintf("%s: missing required field %s", base, quoteStr(f)))
			}
		}
		if !IsSafeAgentID(check.Get("agent_id")) {
			errs.push(base + ".agent_id: expected a canonical lowercase agent ID")
		}
		validateStringArray(check.Get("reviewed_paths"), base+".reviewed_paths", errs, strArrayOpts{allowEmpty: false, pathValue: true})
		if !isVisibleText(check.Get("invariant"), maxTextLength) {
			errs.push(base + ".invariant: invalid text")
		}
		method := check.Get("method")
		isSource := method.IsString() && method.S == "source"
		isLocal := method.IsString() && method.S == "local"
		if !isSource && !isLocal {
			errs.push(base + `.method: expected "source" or "local"`)
		}
		if !isVisibleText(check.Get("result"), maxTextLength) {
			errs.push(base + ".result: invalid text")
		}
		artifact := check.Get("artifact")
		switch {
		case isSource && !isNullV(artifact):
			errs.push(base + ".artifact: source-only check must use null")
		case isLocal:
			if !isOwnedArtifactPath(artifact, check.Get("agent_id")) {
				who := "<agent-id>"
				if IsSafeAgentID(check.Get("agent_id")) {
					who = check.Get("agent_id").S
				}
				errs.push(fmt.Sprintf("%s.artifact: local check requires an artifact owned by agent %s", base, quoteStr(who)))
			}
		case !isSource && !isLocal && !isNullV(artifact) && !IsSafeRelativeSourcePath(artifact):
			errs.push(base + ".artifact: expected null or a safe output-relative path")
		}
	}
}

func validateReviewedPathOwnership(unit *jsonv.Value, base string, errs *errList) {
	rp, lc := unit.Get("reviewed_paths"), unit.Get("local_checks")
	if !rp.IsArray() || !lc.IsArray() {
		return
	}
	var aggregate []string
	aggSet := map[string]bool{}
	for _, p := range rp.A {
		if p.IsString() && !aggSet[p.S] {
			aggSet[p.S] = true
			aggregate = append(aggregate, p.S)
		}
	}
	var owned []string
	ownedSet := map[string]bool{}
	for _, c := range lc.A {
		if !c.IsObject() || !c.Get("reviewed_paths").IsArray() {
			continue
		}
		for _, p := range c.Get("reviewed_paths").A {
			if p.IsString() && !ownedSet[p.S] {
				ownedSet[p.S] = true
				owned = append(owned, p.S)
			}
		}
	}
	for _, p := range aggregate {
		if !ownedSet[p] {
			errs.push(fmt.Sprintf("%s.reviewed_paths: %s has no check owner", base, quoteStr(p)))
		}
	}
	for _, p := range owned {
		if !aggSet[p] {
			errs.push(fmt.Sprintf("%s.local_checks: owned path %s is absent from aggregate reviewed_paths", base, quoteStr(p)))
		}
	}
}

func validateExcludedBlocks(v *jsonv.Value, location string, errs *errList) {
	if !v.IsArray() {
		errs.push(location + ": expected array")
		return
	}
	if len(v.A) > ledgerMaxListItems {
		errs.push(fmt.Sprintf("%s: exceeds %d entries", location, ledgerMaxListItems))
	}
	seen := map[string]bool{}
	for i, entry := range v.A {
		if i >= ledgerMaxListItems {
			break
		}
		base := fmt.Sprintf("%s[%d]", location, i)
		if !entry.IsObject() {
			errs.push(base + ": expected object")
			continue
		}
		if !isVisibleText(entry.Get("block"), maxTextLength) {
			errs.push(base + ".block: invalid text")
		}
		if !isVisibleText(entry.Get("reason"), maxTextLength) {
			errs.push(base + ".reason: invalid text")
		}
		if b := entry.Get("block"); b.IsString() {
			if seen[b.S] {
				errs.push(base + ".block: duplicate entry")
			}
			seen[b.S] = true
		}
	}
}

func semanticKey(unit *jsonv.Value) string {
	items := []*jsonv.Value{unit.Get("surface"), unit.Get("boundary"), unit.Get("subsystem"), unit.Get("attack_class")}
	if unit.Has("lifecycle") {
		items = append(items, unit.Get("lifecycle"))
	} else {
		items = append(items, jsonv.NullValue())
	}
	return string(jsonv.Marshal(jsonv.NewArray(items...), ""))
}

func hasValidSemanticFields(unit *jsonv.Value) bool {
	for _, f := range refFields {
		if !isVisibleText(unit.Get(f), maxTextLength) {
			return false
		}
	}
	return !unit.Has("lifecycle") || isVisibleText(unit.Get("lifecycle"), maxTextLength)
}

func requireEmptyArray(unit *jsonv.Value, field, base string, errs *errList) {
	if a := unit.Get(field); a.IsArray() && len(a.A) > 0 {
		errs.push(fmt.Sprintf("%s.%s: unit with status %s must keep this array empty", base, field, safeQuote(unit.Get("status"))))
	}
}

func requireNonemptyArray(unit *jsonv.Value, field, base string, errs *errList) {
	if a := unit.Get(field); !a.IsArray() || len(a.A) == 0 {
		errs.push(fmt.Sprintf("%s.%s: unit with status %s requires entries", base, field, safeQuote(unit.Get("status"))))
	}
}

func validateStateInvariants(unit *jsonv.Value, base string, errs *errList) {
	emptyEvidence := func() {
		requireEmptyArray(unit, "reviewed_paths", base, errs)
		requireEmptyArray(unit, "local_checks", base, errs)
	}
	requireOwner := func() {
		if !IsSafeAgentID(unit.Get("agent_id")) {
			errs.push(fmt.Sprintf("%s.agent_id: unit with status %s requires a canonical lowercase agent ID", base, safeQuote(unit.Get("status"))))
		}
	}
	status := ""
	if s := unit.Get("status"); s.IsString() {
		status = s.S
	}
	if status != "candidate" {
		requireEmptyArray(unit, "result_fingerprints", base, errs)
	}
	switch status {
	case "planned":
		if !isNullV(unit.Get("agent_id")) {
			errs.push(base + ".agent_id: planned unit must be unassigned")
		}
		emptyEvidence()
		requireEmptyArray(unit, "unresolved", base, errs)
	case "not_applicable", "out_of_scope", "deferred":
		if !isNullV(unit.Get("agent_id")) {
			errs.push(fmt.Sprintf("%s.agent_id: unit with status %s must be unassigned", base, safeQuote(unit.Get("status"))))
		}
		emptyEvidence()
		requireNonemptyArray(unit, "unresolved", base, errs)
	case "in_progress":
		requireOwner()
		emptyEvidence()
		requireEmptyArray(unit, "unresolved", base, errs)
	case "blocked":
		requireOwner()
		requireNonemptyArray(unit, "reviewed_paths", base, errs)
		requireNonemptyArray(unit, "local_checks", base, errs)
		requireNonemptyArray(unit, "unresolved", base, errs)
	case "covered":
		requireOwner()
		requireNonemptyArray(unit, "reviewed_paths", base, errs)
		requireNonemptyArray(unit, "local_checks", base, errs)
		requireEmptyArray(unit, "unresolved", base, errs)
	case "candidate":
		requireOwner()
		requireNonemptyArray(unit, "reviewed_paths", base, errs)
		requireNonemptyArray(unit, "local_checks", base, errs)
		requireNonemptyArray(unit, "result_fingerprints", base, errs)
	}
}

func validateAttempts(v, unit *jsonv.Value, base string, errs *errList) {
	if !v.IsArray() {
		errs.push(base + ".attempts: expected array")
		return
	}
	if len(v.A) > ledgerMaxListItems {
		errs.push(fmt.Sprintf("%s.attempts: exceeds %d entries", base, ledgerMaxListItems))
	}
	priorOwners := map[string]bool{}
	priorArtifacts := map[string]bool{}
	previousWave := 0.0
	for index, attempt := range v.A {
		if index >= ledgerMaxListItems {
			break
		}
		ab := fmt.Sprintf("%s.attempts[%d]", base, index)
		if !attempt.IsObject() {
			errs.push(ab + ": expected object")
			continue
		}
		for _, f := range attemptFields {
			if !attempt.Has(f) {
				errs.push(fmt.Sprintf("%s: missing required field %s", ab, quoteStr(f)))
			}
		}
		wave := attempt.Get("wave")
		if !wave.IsInteger() || wave.N < 1 {
			errs.push(ab + ".wave: expected a positive integer")
		} else {
			if wave.N <= previousWave {
				errs.push(ab + ".wave: archived attempt waves must be strictly increasing")
			}
			if uw := unit.Get("wave"); uw.IsInteger() && wave.N >= uw.N {
				errs.push(fmt.Sprintf("%s.wave: archived attempt wave must precede current wave %s", ab, safeQuote(uw)))
			}
			previousWave = wave.N
		}
		if s := attempt.Get("status"); !(s.IsString() && attemptStatuses[s.S]) {
			errs.push(ab + `.status: expected "covered", "candidate", or "blocked"`)
		}
		hasFreshOwner := false
		aid := attempt.Get("agent_id")
		if !IsSafeAgentID(aid) {
			errs.push(ab + ".agent_id: archived attempt requires a canonical lowercase agent ID")
		} else if priorOwners[aid.S] {
			errs.push(ab + ".agent_id: assignment owner must be fresh for each attempt")
		} else {
			hasFreshOwner = true
		}
		validateStringArray(attempt.Get("reviewed_paths"), ab+".reviewed_paths", errs, strArrayOpts{allowEmpty: true, pathValue: true})
		validateChecks(attempt.Get("local_checks"), ab+".local_checks", errs)
		validateReviewedPathOwnership(attempt, ab, errs)
		validateStringArray(attempt.Get("result_fingerprints"), ab+".result_fingerprints", errs, strArrayOpts{allowEmpty: true, fingerprint: true})
		validateStringArray(attempt.Get("unresolved"), ab+".unresolved", errs, strArrayOpts{allowEmpty: true})
		if !isVisibleText(attempt.Get("reassignment_reason"), maxTextLength) {
			errs.push(ab + ".reassignment_reason: invalid text")
		}
		validateStateInvariants(attempt, ab, errs)
		if lc := attempt.Get("local_checks"); lc.IsArray() {
			for ci, check := range lc.A {
				if !check.IsObject() {
					continue
				}
				if c := check.Get("agent_id"); c.IsString() && priorOwners[c.S] {
					errs.push(fmt.Sprintf("%s.local_checks[%d].agent_id: prior assignment owner evidence must remain in its earlier attempt", ab, ci))
				}
				art := check.Get("artifact")
				if art.IsString() && priorArtifacts[art.S] {
					errs.push(fmt.Sprintf("%s.local_checks[%d].artifact: artifact from an earlier attempt cannot be reused", ab, ci))
				}
				if m := check.Get("method"); m.IsString() && m.S == "local" && art.IsString() {
					priorArtifacts[art.S] = true
				}
			}
		}
		if hasFreshOwner {
			priorOwners[aid.S] = true
		}
	}
	if ua := unit.Get("agent_id"); IsSafeAgentID(ua) && priorOwners[ua.S] {
		errs.push(base + ".agent_id: current assignment owner must be fresh after reassignment")
	}
	if lc := unit.Get("local_checks"); lc.IsArray() {
		for i, check := range lc.A {
			if !check.IsObject() {
				continue
			}
			if c := check.Get("agent_id"); c.IsString() && priorOwners[c.S] {
				errs.push(fmt.Sprintf("%s.local_checks[%d].agent_id: prior assignment owner evidence must remain in its archived attempt", base, i))
			}
			if art := check.Get("artifact"); art.IsString() && priorArtifacts[art.S] {
				errs.push(fmt.Sprintf("%s.local_checks[%d].artifact: artifact from an archived attempt cannot be reused", base, i))
			}
		}
	}
}

func collectUnitErrors(unit *jsonv.Value, index int) []string {
	errs := &errList{}
	base := fmt.Sprintf("$[%d]", index)
	if !unit.IsObject() {
		return []string{base + ": expected object"}
	}
	for _, f := range ledgerRequiredFields {
		if !unit.Has(f) {
			errs.push(fmt.Sprintf("%s: missing required field %s", base, quoteStr(f)))
		}
	}
	for _, f := range refFields {
		if !isVisibleText(unit.Get(f), maxTextLength) {
			errs.push(fmt.Sprintf("%s.%s: invalid text", base, f))
		}
	}
	if unit.Has("lifecycle") && !isVisibleText(unit.Get("lifecycle"), maxTextLength) {
		errs.push(base + ".lifecycle: invalid text")
	}
	expectedID, haveID := "", false
	refs := unit.Get("canonical_refs")
	if !refs.IsObject() {
		errs.push(base + ".canonical_refs: expected object")
	} else {
		expected := refFields
		if refs.Has("lifecycle") {
			expected = append(append([]string(nil), refFields...), "lifecycle")
		}
		for _, f := range expected {
			if !refs.Has(f) {
				errs.push(fmt.Sprintf("%s.canonical_refs: missing required field %s", base, quoteStr(f)))
			} else if !isCanonicalRef(refs.Get(f)) {
				errs.push(fmt.Sprintf("%s.canonical_refs.%s: invalid canonical reference", base, f))
			}
		}
		for _, k := range refs.Keys {
			found := false
			for _, f := range expected {
				if f == k {
					found = true
				}
			}
			if !found {
				errs.push(base + ".canonical_refs: contains unexpected fields")
				break
			}
		}
		if unit.Has("lifecycle") != refs.Has("lifecycle") {
			errs.push(base + ": lifecycle and canonical_refs.lifecycle must appear together")
		}
		expectedID, haveID = CanonicalCoverageID(refs)
	}
	if cid := unit.Get("coverage_id"); !isVisibleText(cid, 65536) {
		errs.push(base + ".coverage_id: invalid text")
	} else if haveID && cid.S != expectedID {
		errs.push(fmt.Sprintf("%s.coverage_id: expected canonical ID %s", base, quoteStr(expectedID)))
	}

	validateStringArray(unit.Get("starting_paths"), base+".starting_paths", errs, strArrayOpts{allowEmpty: false, pathValue: true})
	if o := unit.Get("ordinary_attack_class_block"); !isNullV(o) && !isVisibleText(o, maxTextLength) {
		errs.push(base + ".ordinary_attack_class_block: expected null or non-empty text")
	}
	validateStringArray(unit.Get("selected_companion_blocks"), base+".selected_companion_blocks", errs, strArrayOpts{allowEmpty: true})
	validateExcludedBlocks(unit.Get("excluded_blocks"), base+".excluded_blocks", errs)
	if sel, exc := unit.Get("selected_companion_blocks"), unit.Get("excluded_blocks"); sel.IsArray() && exc.IsArray() {
		selected := map[string]bool{}
		for _, s := range sel.A {
			if s.IsString() {
				selected[s.S] = true
			}
		}
		for bi, entry := range exc.A {
			if entry.IsObject() {
				if b := entry.Get("block"); b.IsString() && selected[b.S] {
					errs.push(fmt.Sprintf("%s.excluded_blocks[%d].block: block is also selected", base, bi))
				}
			}
		}
	}
	if ps := unit.Get("prior_status"); !(ps.IsString() && priorStatuses[ps.S]) {
		errs.push(fmt.Sprintf("%s.prior_status: invalid value %s", base, safeQuote(ps)))
	}
	if s := unit.Get("status"); !(s.IsString() && ledgerStatuses[s.S]) {
		errs.push(fmt.Sprintf("%s.status: invalid value %s", base, safeQuote(s)))
	}
	if w := unit.Get("wave"); !w.IsInteger() || w.N < 1 {
		errs.push(base + ".wave: expected a positive integer")
	}
	if a := unit.Get("agent_id"); !isNullV(a) && !IsSafeAgentID(a) {
		errs.push(base + ".agent_id: expected null or a safe agent ID")
	}

	validateAttempts(unit.Get("attempts"), unit, base, errs)
	validateStringArray(unit.Get("reviewed_paths"), base+".reviewed_paths", errs, strArrayOpts{allowEmpty: true, pathValue: true})
	validateChecks(unit.Get("local_checks"), base+".local_checks", errs)
	validateReviewedPathOwnership(unit, base, errs)
	validateStringArray(unit.Get("result_fingerprints"), base+".result_fingerprints", errs, strArrayOpts{allowEmpty: true, fingerprint: true})
	validateStringArray(unit.Get("unresolved"), base+".unresolved", errs, strArrayOpts{allowEmpty: true})

	validateStateInvariants(unit, base, errs)
	return errs.items
}

func preflightDocument(root *jsonv.Value) []string {
	errs := &errList{}
	type frame struct {
		v        *jsonv.Value
		depth    int
		location string
	}
	stack := []frame{{root, 0, "$"}}
	visited := 0
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		visited++
		if visited > ledgerPreflightValue {
			errs.push(fmt.Sprintf("$: exceeds %d total values", ledgerPreflightValue))
			return errs.items
		}
		if cur.v.Kind != jsonv.Array && cur.v.Kind != jsonv.Object {
			continue
		}
		if cur.depth >= ledgerNestingDepth {
			errs.push(fmt.Sprintf("%s: exceeds nesting depth limit %d", cur.location, ledgerNestingDepth))
			return errs.items
		}
		if cur.v.Kind == jsonv.Array {
			limit := ledgerMaxListItems
			if cur.location == "$" {
				limit = ledgerMaxUnits
			}
			if len(cur.v.A) > limit {
				errs.push(fmt.Sprintf("%s: exceeds %d entries", cur.location, limit))
				return errs.items
			}
			for i := len(cur.v.A) - 1; i >= 0; i-- {
				stack = append(stack, frame{cur.v.A[i], cur.depth + 1, fmt.Sprintf("%s[%d]", cur.location, i)})
			}
			continue
		}
		if len(cur.v.Keys) > ledgerObjectFields {
			errs.push(fmt.Sprintf("%s: exceeds %d object fields", cur.location, ledgerObjectFields))
			return errs.items
		}
		for i := len(cur.v.Keys) - 1; i >= 0; i-- {
			stack = append(stack, frame{cur.v.M[cur.v.Keys[i]], cur.depth + 1, fmt.Sprintf("%s{%d}", cur.location, i)})
		}
	}
	return errs.items
}

// ValidateLedger mirrors validateDocument of validate-coverage-ledger.cjs.
func ValidateLedger(ledger *jsonv.Value) []string {
	errs := &errList{}
	if !ledger.IsArray() {
		errs.push("$: expected a top-level array")
		return errs.items
	}
	if len(ledger.A) > ledgerMaxUnits {
		errs.push(fmt.Sprintf("$: exceeds %d coverage units", ledgerMaxUnits))
		return errs.items
	}
	errs.push(preflightDocument(ledger)...)
	if errs.len() > 0 {
		return errs.items
	}
	type idInfo struct {
		index int
		key   string
		has   bool
	}
	type semInfo struct {
		id    string
		index int
	}
	ids := map[string]idInfo{}
	semantics := map[string]semInfo{}
	previousID, havePrev := "", false
	for index, unit := range ledger.A {
		if errs.len() >= MaxErrors {
			break
		}
		errs.push(collectUnitErrors(unit, index)...)
		if errs.len() >= MaxErrors {
			break
		}
		if !unit.IsObject() || !unit.Get("coverage_id").IsString() {
			continue
		}
		cid := unit.Get("coverage_id").S
		key, hasKey := "", false
		if hasValidSemanticFields(unit) {
			key, hasKey = semanticKey(unit), true
		}
		if prev, ok := ids[cid]; ok {
			qualifier := "duplicate coverage ID"
			if hasKey && prev.has && prev.key != key {
				qualifier = "canonical identity collision with different semantic fields"
			}
			errs.push(fmt.Sprintf("$[%d].coverage_id: %s at $[%d]", index, qualifier, prev.index))
		} else {
			ids[cid] = idInfo{index: index, key: key, has: hasKey}
		}
		if prev, ok := semantics[key]; hasKey && ok && prev.id != cid {
			errs.push(fmt.Sprintf("$[%d].canonical_refs: semantic tuple already uses coverage ID %s at $[%d]", index, quoteStr(prev.id), prev.index))
		} else if hasKey {
			semantics[key] = semInfo{id: cid, index: index}
		}
		if havePrev && utf16Greater(previousID, cid) {
			errs.push(fmt.Sprintf("$[%d].coverage_id: units must be sorted lexicographically", index))
		}
		previousID, havePrev = cid, true
	}
	return errs.items
}
