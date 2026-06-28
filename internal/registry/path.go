package registry

import "strings"

func splitPath(value string) []string {
	value = strings.Trim(value, "/")
	if value == "" {
		return nil
	}
	return strings.Split(value, "/")
}

func lastPathPart(value string) string {
	parts := splitPath(value)
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}
