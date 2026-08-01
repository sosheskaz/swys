package cmd

import "slices"

func sortedKeys[Value any](registry map[string]Value) []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
