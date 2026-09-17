package cmd

import (
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var httpHeaderNames = []string{
	"Accept", "Content-Type", "Accept-Encoding", "Authorization", "Cache-Control",
	"User-Agent", "Host", "Cookie", "Origin", "Referer", "Range", "If-Match",
	"If-None-Match", "If-Modified-Since", "If-Unmodified-Since",
}

var httpHeaderValues = map[string][]string{
	"accept": {
		httpMediaTypeJSON, "text/plain", "text/html", "application/xml", "application/octet-stream", "*/*",
	},
	"content-type": {
		httpMediaTypeJSON, "text/plain", "application/xml", "application/octet-stream",
		"application/x-www-form-urlencoded", "multipart/form-data",
	},
	"accept-encoding": {
		httpCodingGzip, "deflate", httpCodingBrotli, httpCodingZstd, "identity",
	},
	"authorization": {"Bearer ", "Basic "},
	"cache-control": {"no-cache", "no-store", "max-age=", "only-if-cached", "no-transform"},
}

var httpHeaderValueDescriptions = map[string]map[string]string{
	"accept-encoding": {
		"deflate": "request deflate without built-in response decoding",
	},
}

func registerHTTPCompletions(cmd *cobra.Command, options *httpOptions) {
	mustRegisterHTTPCompletion(cmd, "include", completeHTTPInclude(options))
	mustRegisterHTTPCompletion(cmd, httpFormatJSON, completeHTTPJSON)
	mustRegisterHTTPCompletion(cmd, "file", completeHTTPFileField)
	mustRegisterHTTPCompletion(cmd, "header", completeHTTPHeader)
	mustRegisterHTTPCompletion(cmd, "form", noFileHTTPCompletion)
	for _, name := range []string{"data", "resolve", tlsServerNameFlagName, "timeout", "request-timeout", "max-redirects"} {
		mustRegisterHTTPCompletion(cmd, name, noFileHTTPCompletion)
	}
	mustRegisterHTTPCompletion(cmd, "stdin", func(cmd *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		values := []string{httpStdinAuto, httpStdinNever, httpStdinAlways}
		if httpCompletionUsesStdin(cmd, options) {
			values = []string{httpStdinAuto, httpStdinAlways}
		} else if httpCompletionHasBody(cmd, options) {
			values = []string{httpStdinAuto, httpStdinNever}
		}
		return prefixMatches(values, toComplete), cobra.ShellCompDirectiveNoFileComp
	})
	mustRegisterHTTPCompletion(cmd, formatFlagName, func(cmd *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		values := []string{httpFormatText, httpFormatJSON}
		if options.include || httpCompletionEncoding(cmd) != httpEncodingRaw {
			values = []string{httpFormatText}
		}
		return prefixMatchesWithDescriptions(values, structuredFormatDescriptions, toComplete), cobra.ShellCompDirectiveNoFileComp
	})
	mustRegisterHTTPCompletion(cmd, encodingFlagName, func(completionCmd *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		values := byteEncodingNames()
		if options.include || options.format == httpFormatJSON || httpCompletionMethod(completionCmd) == http.MethodHead {
			values = []string{httpEncodingRaw}
		}
		return prefixMatchesWithDescriptions(values, byteEncodingDescriptions, toComplete), cobra.ShellCompDirectiveNoFileComp
	})
	mustRegisterHTTPCompletion(cmd, inputEncodingFlagName, func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		values := byteEncodingNames()
		if len(options.forms) != 0 || len(options.files) != 0 {
			values = []string{httpEncodingRaw}
		}
		return prefixMatchesWithDescriptions(values, byteEncodingDescriptions, toComplete), cobra.ShellCompDirectiveNoFileComp
	})
	cmd.ValidArgsFunction = func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
}

func completeHTTPInclude(options *httpOptions) cobra.CompletionFunc {
	return func(_ *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		var values []string
		for _, value := range []bool{true, false} {
			if value && (options.format == httpFormatJSON || options.encoding != httpEncodingRaw) {
				continue
			}
			candidate := strconv.FormatBool(value)
			if strings.HasPrefix(candidate, prefix) {
				values = append(values, candidate)
			}
		}
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

func mustRegisterHTTPCompletion(cmd *cobra.Command, name string, completion cobra.CompletionFunc) {
	if err := cmd.RegisterFlagCompletionFunc(name, completion); err != nil {
		panic(err)
	}
}

func noFileHTTPCompletion(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveNoFileComp
}

func completeHTTPMethod(cmd *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	values := []string{
		http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace, "QUERY",
	}
	if httpCompletionEncoding(cmd) != httpEncodingRaw {
		values = slices.DeleteFunc(values, func(value string) bool { return value == http.MethodHead })
	}
	return prefixMatches(values, toComplete), cobra.ShellCompDirectiveNoFileComp
}

func completeHTTPJSON(cmd *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if !strings.HasPrefix(toComplete, "@") {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	allow := httpJSONPathAllowed
	if encoding, err := cmd.Flags().GetString(inputEncodingFlagName); err == nil && encoding != httpEncodingRaw {
		allow = func(string) bool { return true }
	}
	paths := completeHTTPPaths(toComplete[1:], allow)
	for index := range paths {
		paths[index] = "@" + paths[index]
	}
	if toComplete == "@" || toComplete == "@-" {
		paths = append([]string{"@-"}, paths...)
	}
	directive := cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	if toComplete == "@-" || httpCompletionTerminalPath(toComplete[1:], allow) {
		directive = cobra.ShellCompDirectiveNoFileComp
	}
	if httpCompletionStdin(cmd) == httpStdinNever {
		paths = slices.DeleteFunc(paths, func(path string) bool { return path == "@-" })
	}
	return paths, directive
}

func httpJSONPathAllowed(name string) bool {
	return strings.EqualFold(filepath.Ext(name), ".json")
}

func completeHTTPFileField(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	name, path, ok := strings.Cut(toComplete, "=")
	if !ok || name == "" {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	paths := completeHTTPPaths(path, func(string) bool { return true })
	for index := range paths {
		paths[index] = name + "=" + paths[index]
	}
	directive := cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	if httpCompletionTerminalPath(path, func(string) bool { return true }) {
		directive = cobra.ShellCompDirectiveNoFileComp
	}
	return paths, directive
}

func httpCompletionTerminalPath(path string, allowFile func(string) bool) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && allowFile(info.Name())
}

func completeHTTPPaths(prefix string, allowFile func(string) bool) []string {
	directory, base := filepath.Split(prefix)
	readDirectory := directory
	if readDirectory == "" {
		readDirectory = "."
	}
	entries, err := os.ReadDir(readDirectory)
	if err != nil {
		return nil
	}
	values := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, base) {
			continue
		}
		value := directory + name
		info, statErr := os.Stat(filepath.Join(readDirectory, name))
		if statErr == nil && info.IsDir() {
			values = append(values, value+string(filepath.Separator))
		} else if allowFile(name) {
			values = append(values, value)
		}
	}
	slices.Sort(values)
	return values
}

func completeHTTPHeader(cmd *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	name, value, hasColon := strings.Cut(toComplete, ":")
	if !hasColon {
		values := make([]string, 0, len(httpHeaderNames))
		for _, candidate := range httpHeaderNames {
			if strings.HasPrefix(strings.ToLower(candidate), strings.ToLower(name)) {
				if strings.EqualFold(candidate, "Content-Type") && httpCompletionHasFiles(cmd) {
					continue
				}
				completion := name + candidate[len(name):] + ": "
				values = append(values, cobra.CompletionWithDesc(completion, "request header"))
			}
		}
		return values, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	}

	common := httpHeaderValues[strings.ToLower(strings.TrimSpace(name))]
	if strings.EqualFold(strings.TrimSpace(name), "Content-Type") && httpCompletionHasFiles(cmd) {
		common = nil
	}
	if len(common) == 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	leading := value[:len(value)-len(strings.TrimLeft(value, " \t"))]
	content := strings.TrimLeft(value, " \t")
	base := name + ":" + leading
	if strings.EqualFold(strings.TrimSpace(name), "Authorization") {
		return prefixMatchesWithBase(common, base, content), cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	}
	if httpListHeader(name) {
		return completeHTTPHeaderList(name, base, content, common), cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	}
	return httpHeaderPrefixMatches(name, common, base, content), cobra.ShellCompDirectiveNoFileComp
}

func httpListHeader(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), "Accept") ||
		strings.EqualFold(strings.TrimSpace(name), "Accept-Encoding") ||
		strings.EqualFold(strings.TrimSpace(name), "Cache-Control")
}

func completeHTTPHeaderList(name, base, content string, common []string) []string {
	comma := strings.LastIndex(content, ",")
	previous := ""
	current := content
	seenContent := ""
	if comma >= 0 {
		previous = content[:comma+1]
		current = strings.TrimLeft(content[comma+1:], " \t")
		seenContent = content[:comma]
	}
	seen := make(map[string]bool)
	for _, item := range strings.Split(seenContent, ",") {
		seen[httpHeaderValueKey(item)] = true
	}
	separator := ""
	if previous != "" {
		separator = " "
	}
	values := make([]string, 0, len(common))
	for _, candidate := range common {
		key := httpHeaderValueKey(candidate)
		if !seen[key] && strings.HasPrefix(strings.ToLower(candidate), strings.ToLower(current)) {
			values = append(values, describeHTTPHeaderValue(base+previous+separator+candidate, name, candidate))
		}
	}
	return values
}

func httpHeaderValueKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if index := strings.IndexByte(value, '='); index >= 0 {
		return value[:index]
	}
	return value
}

func httpHeaderPrefixMatches(name string, values []string, base, prefix string) []string {
	matches := prefixMatchesWithBase(values, base, prefix)
	for index, match := range matches {
		matches[index] = describeHTTPHeaderValue(match, name, strings.TrimPrefix(match, base))
	}
	return matches
}

func describeHTTPHeaderValue(completion, name, value string) string {
	descriptions := httpHeaderValueDescriptions[strings.ToLower(strings.TrimSpace(name))]
	if description := descriptions[strings.ToLower(value)]; description != "" {
		return cobra.CompletionWithDesc(completion, description)
	}
	return completion
}

func prefixMatches(values []string, prefix string) []string {
	return prefixMatchesWithBase(values, "", prefix)
}

func prefixMatchesWithDescriptions(values []string, descriptions map[string]string, prefix string) []string {
	return completionsWithDescriptions(prefixMatches(values, prefix), descriptions)
}

func prefixMatchesWithBase(values []string, base, prefix string) []string {
	matches := make([]string, 0, len(values))
	for _, value := range values {
		if strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)) {
			completion := base + value
			if strings.HasSuffix(value, " ") {
				completion = cobra.CompletionWithDesc(completion, "type credentials after the scheme")
			}
			matches = append(matches, completion)
		}
	}
	return matches
}

func httpCompletionHasBody(cmd *cobra.Command, options *httpOptions) bool {
	return cmd.Flags().Changed("input") || cmd.Flags().Changed("data") || cmd.Flags().Changed(httpFormatJSON) || len(options.forms) != 0 || len(options.files) != 0
}

func httpCompletionUsesStdin(cmd *cobra.Command, options *httpOptions) bool {
	return cmd.Flags().Changed("input") && cmd.Flag("input").Value.String() == "-" || cmd.Flags().Changed(httpFormatJSON) && options.jsonData == "@-"
}

func httpCompletionMethod(cmd *cobra.Command) string {
	return httpCompletionString(cmd, "method")
}

func httpCompletionEncoding(cmd *cobra.Command) string {
	return httpCompletionString(cmd, encodingFlagName)
}

func httpCompletionStdin(cmd *cobra.Command) string {
	return httpCompletionString(cmd, "stdin")
}

func httpCompletionHasFiles(cmd *cobra.Command) bool {
	return len(httpCompletionStringArray(cmd, "file")) != 0
}

func prepareHTTPCompletion(completionCmd *cobra.Command, args []string) {
	if (completionCmd.Name() != cobra.ShellCompRequestCmd && completionCmd.Name() != cobra.ShellCompNoDescRequestCmd) || len(args) == 0 {
		return
	}

	completedArgs := args[:len(args)-1]
	probeRoot := newRootCmd()
	probeCommand, probeArgs, err := probeRoot.Find(completedArgs)
	if err != nil || !commandHasShape(probeCommand, httpRequestShape) {
		return
	}
	if err := probeCommand.ParseFlags(probeArgs); err != nil {
		return
	}
	actualCommand, _, err := completionCmd.Root().Find(completedArgs)
	if err != nil || !commandHasShape(actualCommand, httpRequestShape) {
		return
	}

	hide := func(names ...string) {
		for _, name := range names {
			if flag := actualCommand.Flags().Lookup(name); flag != nil {
				flag.Hidden = true
			}
		}
	}
	prepareHTTPOutputCompletion(probeCommand, hide)
	prepareHTTPBodyCompletion(probeCommand, hide)
}

func prepareHTTPOutputCompletion(cmd *cobra.Command, hide func(...string)) {
	format := httpCompletionString(cmd, formatFlagName)
	encoding := httpCompletionString(cmd, encodingFlagName)
	if format == httpFormatJSON || encoding != httpEncodingRaw {
		hide("include")
	}
}

func prepareHTTPBodyCompletion(cmd *cobra.Command, hide func(...string)) {
	stdin := httpCompletionString(cmd, "stdin")
	if stdin == httpStdinAlways && !httpCompletionProbeUsesStdin(cmd) {
		hide("input", "data", httpFormatJSON, "form", "file")
	}
	inputEncoding := httpCompletionString(cmd, inputEncodingFlagName)
	if inputEncoding != httpEncodingRaw {
		hide("form", "file")
	}
	headers := httpCompletionStringArray(cmd, "header")
	if slices.ContainsFunc(headers, httpCompletionIsContentType) {
		hide("file")
	}
}

func httpCompletionProbeUsesStdin(cmd *cobra.Command) bool {
	input := httpCompletionString(cmd, "input")
	jsonData := httpCompletionString(cmd, httpFormatJSON)
	return cmd.Flags().Changed("input") && input == "-" || cmd.Flags().Changed(httpFormatJSON) && jsonData == "@-"
}

func httpCompletionIsContentType(value string) bool {
	name, _, ok := strings.Cut(value, ":")
	return ok && strings.EqualFold(strings.TrimSpace(name), "Content-Type")
}

func httpCompletionString(cmd *cobra.Command, name string) string {
	value, err := cmd.Flags().GetString(name)
	if err != nil {
		return ""
	}
	return value
}

func httpCompletionStringArray(cmd *cobra.Command, name string) []string {
	values, err := cmd.Flags().GetStringArray(name)
	if err != nil {
		return nil
	}
	return values
}
