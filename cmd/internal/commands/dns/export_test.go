package dns

import "github.com/sosheskaz-systems/npc/internal/dnsquery"

func DirectRecordTypesForTest() []string { return directDNSRecordTypes() }

func RenderResultForTest(result *dnsquery.Result, format string, short bool) ([]byte, error) {
	return renderDNSResult(result, format, short)
}
