package dns

import "github.com/sosheskaz/swys/internal/dnsquery"

func DirectRecordTypesForTest() []string { return directDNSRecordTypes() }

func RenderResultForTest(result *dnsquery.Result, format string, short bool) ([]byte, error) {
	selection := "result"
	if short {
		selection = "values"
	}
	selected := selectDNSResult(result, selection)
	return renderDNSResult(selected, format)
}
