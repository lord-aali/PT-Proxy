package ini

import (
	"os"
	"strings"
)

func LoadIniFile(path string) map[string]string {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	configMap := make(map[string]string)
	config := string(bytes)
	lines := strings.Split(config, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || len(line) == 0 {
			continue
		}
		s := strings.Split(line, "=")
		configMap[s[0]] = s[1]
	}
	return configMap
}
