package validate

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/xsec-labs/xsec-plugin-code-audit/sidecar/internal/jsonv"
)

// ReportSchemaJSON is the upstream report-schema.json (pinned commit c1c8a8c), embedded verbatim.
//
//go:embed report-schema.json
var ReportSchemaJSON []byte

// Findings limits, same as the upstream LIMITS.
const (
	findingsNestingDepth = 64
	findingsArrayItems   = 1000
	canonicalKeyBytes    = 1024 * 1024
	uniqueSetBytes       = 5 * 1024 * 1024
)

var supportedTypes = map[string]bool{"object": true, "array": true, "string": true, "integer": true, "number": true, "boolean": true, "null": true}
var supportedKeywords = map[string]bool{
	"$comment": true, "additionalProperties": true, "const": true, "description": true, "enum": true, "items": true,
	"minimum": true, "minItems": true, "minLength": true, "oneOf": true, "pattern": true, "properties": true,
	"required": true, "type": true, "uniqueItems": true, "visibleContent": true,
}

var severityRank = map[string]int{"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

var (
	schemaOnce sync.Once
	schemaVal  *jsonv.Value
	schemaErr  error
)

// Schema returns the parsed embedded schema.
func Schema() (*jsonv.Value, error) {
	schemaOnce.Do(func() {
		schemaVal, schemaErr = jsonv.Parse(ReportSchemaJSON)
		if schemaErr == nil {
			if errs := CollectSchemaErrors(schemaVal, "schema"); len(errs) > 0 {
				schemaErr = fmt.Errorf("unsupported or invalid report schema: %s", strings.Join(errs, "; "))
			}
		}
	})
	return schemaVal, schemaErr
}

var identPath = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func propertyPath(base, key string) string {
	if identPath.MatchString(key) {
		return base + "." + key
	}
	return base + "[" + quoteStr(key) + "]"
}

// CollectSchemaErrors checks that the schema only uses keywords the interpreter supports.
func CollectSchemaErrors(schema *jsonv.Value, location string) []string {
	errs := &errList{}
	var check func(node *jsonv.Value, p string)
	check = func(node *jsonv.Value, p string) {
		if !node.IsObject() {
			errs.push(p + ": schema must be an object")
			return
		}
		for _, k := range node.Keys {
			if !supportedKeywords[k] {
				errs.push(fmt.Sprintf("%s: unsupported schema keyword %s", p, quoteStr(k)))
			}
		}
		if n := node.Get("$comment"); n != nil && !n.IsString() {
			errs.push(p + ".$comment: expected string")
		}
		if n := node.Get("description"); n != nil && !n.IsString() {
			errs.push(p + ".description: expected string")
		}
		if n := node.Get("type"); n != nil && (!n.IsString() || !supportedTypes[n.S]) {
			errs.push(fmt.Sprintf("%s.type: unsupported type %s", p, safeQuote(n)))
		}
		if props := node.Get("properties"); props != nil {
			if !props.IsObject() {
				errs.push(p + ".properties: expected object")
			} else {
				for _, k := range props.Keys {
					check(props.M[k], propertyPath(p+".properties", k))
				}
			}
		}
		if req := node.Get("required"); req != nil {
			ok := req.IsArray()
			if ok {
				for _, e := range req.A {
					if !e.IsString() {
						ok = false
					}
				}
			}
			if !ok {
				errs.push(p + ".required: expected an array of strings")
			} else {
				seen := map[string]bool{}
				dup := false
				for _, e := range req.A {
					if seen[e.S] {
						dup = true
					}
					seen[e.S] = true
				}
				if dup {
					errs.push(p + ".required: entries must be unique")
				}
			}
		}
		if ap := node.Get("additionalProperties"); ap != nil && ap.Kind != jsonv.Bool {
			errs.push(p + ".additionalProperties: only boolean values are supported")
		}
		if en := node.Get("enum"); en != nil {
			if !en.IsArray() || len(en.A) == 0 {
				errs.push(p + ".enum: expected a non-empty array")
			} else {
				seen := map[string]bool{}
				for _, e := range en.A {
					key, _, err := jsonv.Canonical(e, canonicalKeyBytes)
					if err != nil {
						errs.push(p + ".enum: " + err.Error())
						break
					}
					if seen[key] {
						errs.push(p + ".enum: entries must be unique")
						break
					}
					seen[key] = true
				}
			}
		}
		if it := node.Get("items"); it != nil {
			check(it, p+".items")
		}
		for _, kw := range []string{"minItems", "minLength"} {
			if n := node.Get(kw); n != nil && (!n.IsInteger() || n.N < 0) {
				errs.push(fmt.Sprintf("%s.%s: expected a non-negative integer", p, kw))
			}
		}
		if n := node.Get("minimum"); n != nil && (n.Kind != jsonv.Number || isNonFinite(n.N)) {
			errs.push(p + ".minimum: expected a finite number")
		}
		if pat := node.Get("pattern"); pat != nil {
			if !pat.IsString() {
				errs.push(p + ".pattern: expected string")
			} else if _, err := regexp.Compile(pat.S); err != nil {
				errs.push(p + ".pattern: invalid regular expression")
			}
		}
		if u := node.Get("uniqueItems"); u != nil && u.Kind != jsonv.Bool {
			errs.push(p + ".uniqueItems: expected boolean")
		}
		if vc := node.Get("visibleContent"); vc != nil {
			if vc.Kind != jsonv.Bool {
				errs.push(p + ".visibleContent: expected boolean")
			} else if vc.B {
				if t := node.Get("type"); t == nil || !t.IsString() || t.S != "string" {
					errs.push(p + `.visibleContent: requires type "string"`)
				}
			}
		}
		if one := node.Get("oneOf"); one != nil {
			if !one.IsArray() || len(one.A) == 0 {
				errs.push(p + ".oneOf: expected a non-empty array")
			} else {
				for i, br := range one.A {
					check(br, fmt.Sprintf("%s.oneOf[%d]", p, i))
				}
			}
		}
	}
	check(schema, location)
	return errs.items
}

type discriminator struct {
	key   string
	value *jsonv.Value
}

func findDiscriminator(schema *jsonv.Value) *discriminator {
	props := schema.Get("properties")
	if props == nil || !props.IsObject() {
		return nil
	}
	for _, k := range props.Keys {
		sub := props.M[k]
		if sub.IsObject() && sub.Has("const") {
			return &discriminator{key: k, value: sub.Get("const")}
		}
	}
	return nil
}

var patternCache sync.Map

func compilePattern(p string) *regexp.Regexp {
	if c, ok := patternCache.Load(p); ok {
		return c.(*regexp.Regexp)
	}
	re := regexp.MustCompile(p)
	patternCache.Store(p, re)
	return re
}

func typeOf(v *jsonv.Value) string { return v.TypeName() }

func validateNode(value, schema *jsonv.Value, p string, errs *errList) {
	if errs.len() >= MaxErrors {
		return
	}
	if one := schema.Get("oneOf"); one != nil {
		results := make([][]string, len(one.A))
		passing := 0
		for i, br := range one.A {
			e := &errList{}
			validateNode(value, br, p, e)
			results[i] = e.items
			if len(e.items) == 0 {
				passing++
			}
		}
		if passing != 1 {
			errs.push(fmt.Sprintf("%s: must match exactly one schema in oneOf; matched %d", p, passing))
			if passing == 0 && value.IsObject() {
				var matching []int
				for i, br := range one.A {
					d := findDiscriminator(br)
					if d != nil && value.Has(d.key) && jsonv.DeepEqual(value.Get(d.key), d.value) {
						matching = append(matching, i)
					}
				}
				if len(matching) == 1 {
					errs.push(results[matching[0]]...)
				}
			}
		}
	}
	if c := schema.Get("const"); c != nil && !jsonv.DeepEqual(value, c) {
		errs.push(fmt.Sprintf("%s: must equal %s, got %s", p, safeQuote(c), safeQuote(value)))
	}
	if en := schema.Get("enum"); en != nil {
		found := false
		for _, a := range en.A {
			if jsonv.DeepEqual(value, a) {
				found = true
				break
			}
		}
		if !found {
			parts := make([]string, len(en.A))
			for i, a := range en.A {
				parts[i] = safeQuote(a)
			}
			errs.push(fmt.Sprintf("%s: invalid value %s (expected one of %s)", p, safeQuote(value), strings.Join(parts, ", ")))
		}
	}
	if t := schema.Get("type"); t != nil {
		want := t.S
		got := typeOf(value)
		if got != want && !(want == "integer" && value.Kind == jsonv.Number && value.IsInteger()) {
			errs.push(fmt.Sprintf("%s: expected %s, got %s", p, want, got))
			return
		}
	}
	if value.IsObject() {
		if req := schema.Get("required"); req != nil {
			for _, r := range req.A {
				if !value.Has(r.S) {
					errs.push(fmt.Sprintf("%s: missing required field %s", p, quoteStr(r.S)))
				}
			}
		}
		props := schema.Get("properties")
		for _, key := range value.Keys {
			if props != nil && props.Has(key) {
				validateNode(value.M[key], props.M[key], propertyPath(p, key), errs)
			} else if ap := schema.Get("additionalProperties"); ap != nil && ap.Kind == jsonv.Bool && !ap.B {
				errs.push(fmt.Sprintf("%s: unexpected field %s", p, quoteStr(key)))
			}
		}
	}
	if value.IsArray() {
		if mi := schema.Get("minItems"); mi != nil && float64(len(value.A)) < mi.N {
			errs.push(fmt.Sprintf("%s: must have at least %s item(s), got %d", p, jsonv.JSNumber(mi.N), len(value.A)))
		}
		if u := schema.Get("uniqueItems"); u != nil && u.B {
			seen := map[string]bool{}
			setBytes := 0
			for i, item := range value.A {
				key, n, err := jsonv.Canonical(item, canonicalKeyBytes)
				if err != nil {
					errs.push(fmt.Sprintf("%s[%d]: %s", p, i, err.Error()))
					break
				}
				if seen[key] {
					errs.push(fmt.Sprintf("%s: items must be unique; duplicate at index %d", p, i))
					continue
				}
				setBytes += n
				if setBytes > uniqueSetBytes {
					errs.push(fmt.Sprintf("%s: canonical uniqueness set exceeds %d byte limit", p, uniqueSetBytes))
					break
				}
				seen[key] = true
			}
		}
		if it := schema.Get("items"); it != nil {
			for i, item := range value.A {
				validateNode(item, it, fmt.Sprintf("%s[%d]", p, i), errs)
			}
		}
	}
	if value.IsString() {
		if ml := schema.Get("minLength"); ml != nil && float64(jsonv.CodePointLen(value.S)) < ml.N {
			errs.push(fmt.Sprintf("%s: must have at least %s character(s)", p, jsonv.JSNumber(ml.N)))
		}
		if vc := schema.Get("visibleContent"); vc != nil && vc.B {
			if !hasValidScalars(value.S) {
				errs.push(p + ": must contain only valid Unicode scalar values")
			} else if !HasVisibleProse(value.S) {
				errs.push(p + ": must contain a visible character")
			}
		}
		if pat := schema.Get("pattern"); pat != nil && !compilePattern(pat.S).MatchString(value.S) {
			errs.push(fmt.Sprintf("%s: must match pattern %s", p, string(jsonv.Marshal(jsonv.Str(pat.S), ""))))
		}
	}
	if value.Kind == jsonv.Number {
		if mn := schema.Get("minimum"); mn != nil && value.N < mn.N {
			errs.push(fmt.Sprintf("%s: must be at least %s, got %s", p, jsonv.JSNumber(mn.N), jsonv.JSNumber(value.N)))
		}
	}
}

func collectUnchecked(value, schema *jsonv.Value, p string) []string {
	e := &errList{}
	validateNode(value, schema, p, e)
	return e.items
}

// dataLimitErrors mirrors collectDataLimitErrors (nesting depth and array length).
func dataLimitErrors(value *jsonv.Value, location string) []string {
	type frame struct {
		v        *jsonv.Value
		location string
		depth    int
	}
	depth := 0
	if value.Kind == jsonv.Array || value.Kind == jsonv.Object {
		depth = 1
	}
	stack := []frame{{value, location, depth}}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if cur.v.Kind != jsonv.Array && cur.v.Kind != jsonv.Object {
			continue
		}
		if cur.depth > findingsNestingDepth {
			return []string{escapeUnsafe(fmt.Sprintf("%s: exceeds %d level nesting depth limit", cur.location, findingsNestingDepth))}
		}
		if cur.v.Kind == jsonv.Array {
			if len(cur.v.A) > findingsArrayItems {
				return []string{escapeUnsafe(fmt.Sprintf("%s: exceeds %d item array limit", cur.location, findingsArrayItems))}
			}
			for i := len(cur.v.A) - 1; i >= 0; i-- {
				c := cur.v.A[i]
				if c.Kind == jsonv.Array || c.Kind == jsonv.Object {
					stack = append(stack, frame{c, fmt.Sprintf("%s[%d]", cur.location, i), cur.depth + 1})
				}
			}
		} else {
			for i := len(cur.v.Keys) - 1; i >= 0; i-- {
				k := cur.v.Keys[i]
				c := cur.v.M[k]
				if c.Kind == jsonv.Array || c.Kind == jsonv.Object {
					stack = append(stack, frame{c, propertyPath(cur.location, k), cur.depth + 1})
				}
			}
		}
	}
	return nil
}

func collectFindingSemanticErrors(findings *jsonv.Value) []string {
	errs := &errList{}
	if !findings.IsArray() {
		return errs.items
	}
	fingerprints := map[string]int{}
	previous := ""
	havePrevious := false
	for index, finding := range findings.A {
		if errs.len() >= MaxErrors {
			break
		}
		if !finding.IsObject() {
			continue
		}
		base := fmt.Sprintf("$[%d]", index)
		if fp := finding.Get("fingerprint"); fp.IsString() {
			if first, ok := fingerprints[fp.S]; ok {
				errs.push(fmt.Sprintf("%s.fingerprint: duplicate of $[%d].fingerprint", base, first))
			} else {
				fingerprints[fp.S] = index
			}
			if havePrevious && utf16Greater(previous, fp.S) {
				errs.push(base + ".fingerprint: findings must be sorted lexicographically")
			}
			previous, havePrevious = fp.S, true
		}
		for _, field := range []string{"trace", "evidence"} {
			arr := finding.Get(field)
			if !arr.IsArray() {
				continue
			}
			for ei, entry := range arr.A {
				if !entry.IsObject() {
					continue
				}
				if entry.Has("line") {
					l := entry.Get("line")
					if !l.IsInteger() || l.N < 1 {
						errs.push(fmt.Sprintf("%s.%s[%d].line: must be a positive integer", base, field, ei))
					}
				}
				if entry.Has("file") && !IsSafeRelativeSourcePath(entry.Get("file")) {
					errs.push(fmt.Sprintf("%s.%s[%d].file: must be a safe repository-relative source path", base, field, ei))
				}
			}
		}
		if rem := finding.Get("remediation"); rem != nil && rem.Kind != jsonv.Null {
			if cc := rem.Get("code_changes"); cc.IsArray() {
				for ci, ch := range cc.A {
					if ch != nil && ch.Kind != jsonv.Null && ch.Has("file_name") && !IsSafeRelativeSourcePath(ch.Get("file_name")) {
						errs.push(fmt.Sprintf("%s.remediation.code_changes[%d].file_name: must be a safe repository-relative source path", base, ci))
					}
				}
			}
		}
		if trace := finding.Get("trace"); trace.IsArray() && len(trace.A) == 1 {
			kind := traceKind(trace.A[0])
			if kind == nil || (kind.S != "entrypoint" && kind.S != "sink") || kind.Kind != jsonv.String {
				errs.push(base + `.trace[0].kind: a one-line trace must be "entrypoint" or "sink"`)
			}
		} else if trace.IsArray() && len(trace.A) > 1 {
			last := len(trace.A) - 1
			if traceTruthy(trace.A[0]) && !isKind(trace.A[0], "entrypoint") {
				errs.push(fmt.Sprintf(`%s.trace[0].kind: must be "entrypoint", got %s`, base, safeQuoteOrUndefined(traceKind(trace.A[0]))))
			}
			if traceTruthy(trace.A[last]) && !isKind(trace.A[last], "sink") {
				errs.push(fmt.Sprintf(`%s.trace[%d].kind: must be "sink", got %s`, base, last, safeQuoteOrUndefined(traceKind(trace.A[last]))))
			}
			for ti := 1; ti < last; ti++ {
				if traceTruthy(trace.A[ti]) && !isKind(trace.A[ti], "propagation") {
					errs.push(fmt.Sprintf(`%s.trace[%d].kind: must be "propagation", got %s`, base, ti, safeQuoteOrUndefined(traceKind(trace.A[ti]))))
				}
			}
		}
		verdict := finding.Get("verdict")
		verdictStr := ""
		if verdict.IsString() {
			verdictStr = verdict.S
		}
		switch verdictStr {
		case "confirmed":
			for _, f := range []string{"claimed_root_cause", "blockers", "validation_plan", "reason"} {
				if finding.Has(f) {
					errs.push(fmt.Sprintf("%s: confirmed finding must not contain %s", base, quoteStr(f)))
				}
			}
			ex := finding.Get("execution")
			if !ex.IsObject() || !ex.Get("observed_result").IsString() || !HasVisibleProse(ex.Get("observed_result").S) {
				errs.push(base + ": confirmed finding requires a visible execution observed_result")
			}
			rem := finding.Get("remediation")
			if !rem.IsObject() || !rem.Get("strategy").IsString() || !HasVisibleProse(rem.Get("strategy").S) {
				errs.push(base + ": confirmed finding requires visible remediation")
			}
			sev := finding.Get("severity")
			overall := sev.Get("overall_severity")
			impact := sev.Get("impact").Get("score")
			if overall.IsString() && impact.IsString() {
				ro, ok1 := severityRank[overall.S]
				ri, ok2 := severityRank[impact.S]
				if ok1 && ok2 && ro > ri {
					errs.push(fmt.Sprintf("%s.severity.overall_severity: cannot exceed demonstrated impact %s", base, safeQuote(impact)))
				}
			}
		case "needs_validation":
			if finding.Has("severity") {
				errs.push(base + `: needs_validation finding must not contain "severity"`)
			}
			for _, f := range []string{"execution", "remediation", "reason", "root_cause"} {
				if finding.Has(f) {
					errs.push(fmt.Sprintf("%s: needs_validation finding must not contain %s", base, quoteStr(f)))
				}
			}
			plan := finding.Get("validation_plan")
			hasLocal := plan.IsObject() && plan.Get("local").IsString() && HasVisibleProse(plan.Get("local").S)
			hasDeploy := plan.IsObject() && plan.Get("deployment").IsString() && HasVisibleProse(plan.Get("deployment").S)
			if !hasLocal && !hasDeploy {
				errs.push(base + ".validation_plan: requires at least one visible local or deployment plan")
			}
		case "rejected":
			for _, f := range []string{"severity", "execution", "remediation", "blockers", "validation_plan", "root_cause"} {
				if finding.Has(f) {
					errs.push(fmt.Sprintf("%s: rejected finding must not contain %s", base, quoteStr(f)))
				}
			}
		}
	}
	return errs.items
}

func traceKind(entry *jsonv.Value) *jsonv.Value {
	if entry == nil || !entry.IsObject() {
		return nil
	}
	return entry.Get("kind")
}

// traceTruthy mirrors a JS truthiness check on a trace entry (only objects, arrays, non-empty strings, numbers
// and true are truthy; the upstream code then reads .kind which is undefined for non-objects).
func traceTruthy(entry *jsonv.Value) bool {
	if entry == nil {
		return false
	}
	switch entry.Kind {
	case jsonv.Null:
		return false
	case jsonv.Bool:
		return entry.B
	case jsonv.Number:
		return entry.N != 0 && entry.N == entry.N
	case jsonv.String:
		return entry.S != ""
	}
	return true
}

func isKind(entry *jsonv.Value, want string) bool {
	k := traceKind(entry)
	return k != nil && k.IsString() && k.S == want
}

func safeQuoteOrUndefined(v *jsonv.Value) string {
	if v == nil {
		return `"<undefined>"`
	}
	return safeQuote(v)
}

// utf16Greater compares like JavaScript's > on strings (by UTF-16 code units).
func utf16Greater(a, b string) bool {
	ua, ub := toUTF16(a), toUTF16(b)
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] > ub[i]
		}
	}
	return len(ua) > len(ub)
}

// ValidateFindings mirrors validateDocument for findings.json.
func ValidateFindings(findings *jsonv.Value) ([]string, error) {
	schema, err := Schema()
	if err != nil {
		return nil, err
	}
	if lim := dataLimitErrors(findings, "$"); len(lim) > 0 {
		return lim, nil
	}
	errs := &errList{items: collectUnchecked(findings, schema, "$")}
	if errs.len() < MaxErrors {
		errs.push(collectFindingSemanticErrors(findings)...)
	}
	return errs.items, nil
}
