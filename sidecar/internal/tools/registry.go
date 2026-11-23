package tools

// All returns every tool, in the order tools/list reports them.
func All() []*Tool {
	return []*Tool{
		runStart(), runUpdate(), architecturePut(), agentNote(), runsList(), runGet(), runDelete(),
		ledgerPut(), coverageGet(),
		findingsPut(), findingsList(), findingGet(), findingStateSet(),
		validateTool(), reportBuild(), exportTool(),
	}
}
