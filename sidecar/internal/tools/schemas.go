package tools

// JSON Schemas of the tool arguments. Handlers re-check every field (strictKeys, types, ranges), so a schema
// is guidance for the model and the host UI, not the only line of defence.

const schemaRunOnly = `{"type":"object","properties":{"run_id":{"type":"string","description":"<repo>/run-<N>"}},"required":["run_id"],"additionalProperties":false}`

const schemaRunStart = `{"type":"object","properties":{
"target":{"type":"string","description":"Absolute path of the source tree to audit. Only read, never executed."},
"profile":{"type":"string","enum":["quick","standard","deep"]},
"scope":{"type":"object","properties":{"mode":{"type":"string","enum":["repo","paths","diff"]},"paths":{"type":"array","items":{"type":"string"}},"base":{"type":"string"},"head":{"type":"string"}},"additionalProperties":false},
"budget":{"type":"integer","minimum":1,"maximum":100000,"description":"Maximum sub-agent invocations for the run."},
"focus":{"type":"array","items":{"type":"string"},"description":"Free-text areas the user wants emphasised."},
"source_ref":{"type":"object","properties":{"commit":{"type":"string"},"dirty":{"type":"boolean"}},"additionalProperties":false},
"repo":{"type":"string","description":"Override the repository name used to group runs."},
"companions":{"type":"array","items":{"type":"string"},"description":"Selected companion file names of the skill."}
},"required":["target"],"additionalProperties":false}`

const schemaRunUpdate = `{"type":"object","properties":{
"run_id":{"type":"string"},
"phase":{"type":"string","enum":["recon","hunt","validate","output","verify","report"]},
"status":{"type":"string","enum":["in_progress","incomplete"]},
"incomplete_reason":{"type":"string"},
"budget":{"type":"integer","minimum":1,"maximum":100000},
"note":{"type":"string"}
},"required":["run_id"],"additionalProperties":false}`

const schemaArchitecturePut = `{"type":"object","properties":{"run_id":{"type":"string"},"markdown":{"type":"string"}},"required":["run_id","markdown"],"additionalProperties":false}`

const schemaAgentNote = `{"type":"object","properties":{
"run_id":{"type":"string"},
"event":{"type":"string","enum":["dispatched","returned","failed"]},
"agent_id":{"type":"string","description":"Canonical lowercase id, unique per delegation."},
"role":{"type":"string","enum":["recon","hunter","critic","verifier","record_verifier"]},
"phase":{"type":"string","enum":["recon","hunt","validate","output","verify","report"]},
"unit_ids":{"type":"array","items":{"type":"string"}},
"summary":{"type":"string"}
},"required":["run_id","event","agent_id","role"],"additionalProperties":false}`

const schemaRunsList = `{"type":"object","properties":{"repo":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":500}},"additionalProperties":false}`

const schemaRunGet = `{"type":"object","properties":{"run_id":{"type":"string"},"include_architecture":{"type":"boolean"},"include_agents":{"type":"boolean"}},"required":["run_id"],"additionalProperties":false}`

const schemaLedgerPut = `{"type":"object","properties":{
"run_id":{"type":"string"},
"units":{"type":"array","items":{"type":"object"},"description":"Coverage units exactly as the skill's coverage-ledger format defines them. coverage_id may be omitted: it is derived from canonical_refs."},
"mode":{"type":"string","enum":["upsert","replace"],"description":"upsert (default) merges units by coverage_id into the stored ledger; replace stores exactly the given units."},
"remove":{"type":"array","items":{"type":"string"},"description":"coverage_ids to drop (upsert mode)."}
},"required":["run_id"],"additionalProperties":false}`

const schemaCoverageGet = `{"type":"object","properties":{
"run_id":{"type":"string"},
"status":{"type":"string","enum":["planned","not_applicable","out_of_scope","in_progress","covered","candidate","blocked","deferred"]},
"coverage_id":{"type":"string","description":"Return only this unit."},
"summary_only":{"type":"boolean"},
"limit":{"type":"integer","minimum":1,"maximum":1000},
"offset":{"type":"integer","minimum":0,"maximum":100000}
},"required":["run_id"],"additionalProperties":false}`

const schemaFindingsPut = `{"type":"object","properties":{
"run_id":{"type":"string"},
"records":{"type":"array","items":{"type":"object"},"description":"Finding records of the confirmed, needs_validation or rejected branches of report-schema.json. Every file/line is checked against the target source."},
"mode":{"type":"string","enum":["upsert","replace"],"description":"upsert (default) merges by fingerprint; replace stores exactly the given records."},
"remove":{"type":"array","items":{"type":"string"},"description":"Fingerprints to drop (upsert mode)."}
},"required":["run_id"],"additionalProperties":false}`

const schemaFindingsList = `{"type":"object","properties":{
"run_id":{"type":"string"},
"verdict":{"type":"string","enum":["confirmed","needs_validation","rejected"]},
"severity":{"type":"string","enum":["informational","low","medium","high","critical"]},
"query":{"type":"string","description":"Substring of title, description or a file path."},
"limit":{"type":"integer","minimum":1,"maximum":500},
"offset":{"type":"integer","minimum":0,"maximum":100000}
},"required":["run_id"],"additionalProperties":false}`

const schemaFindingGet = `{"type":"object","properties":{"run_id":{"type":"string"},"fingerprint":{"type":"string"}},"required":["run_id","fingerprint"],"additionalProperties":false}`

const schemaFindingState = `{"type":"object","properties":{
"run_id":{"type":"string"},
"fingerprint":{"type":"string"},
"fix_status":{"type":"string","enum":["proposed","fixed","still_present","cannot_determine","none"],"description":"none clears it."},
"fix_note":{"type":"string"},
"user_decision":{"type":"string","enum":["confirmed_by_user","excluded_by_user","none"],"description":"none clears it."},
"user_note":{"type":"string"},
"vuln_id":{"type":"string","description":"Id of the project vulnerability this finding was linked to; empty string unlinks."}
},"required":["run_id","fingerprint"],"additionalProperties":false}`

const schemaReportBuild = `{"type":"object","properties":{
"run_id":{"type":"string"},
"language":{"type":"string","enum":["zh","en"],"description":"Language of the generated headings (default zh)."},
"summary":{"type":"string","description":"Optional executive summary (Markdown) placed at the top of REPORT.md."}
},"required":["run_id"],"additionalProperties":false}`

const schemaExport = `{"type":"object","properties":{
"run_id":{"type":"string"},
"format":{"type":"string","enum":["sarif","csv","markdown","json"]},
"include_needs_validation":{"type":"boolean"}
},"required":["run_id","format"],"additionalProperties":false}`

const schemaReportRead = `{"type":"object","properties":{"run_id":{"type":"string"},"name":{"type":"string","enum":["REPORT.md","FINDINGS-DETAIL.md","NEEDS-VALIDATION.md","architecture.md"]}},"required":["run_id","name"],"additionalProperties":false}`
