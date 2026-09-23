package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/meklis/dhcp-radius-server/api"
	"github.com/meklis/dhcp-radius-server/radius"
	"github.com/meklis/dhcp-radius-server/script"
	"gopkg.in/yaml.v2"
)

const (
	ProcessorAPI    = "api"
	ProcessorScript = "script"
)

type Configuration struct {
	Logger struct {
		Console struct {
			PrintFile   bool `yaml:"print_file"`
			EnableColor bool `yaml:"enable_color"`
			LogLevel    int  `yaml:"log_level"`
			Enabled     bool `yaml:"enabled"`
		} `yaml:"console"`
	} `yaml:"logger"`
	Prometheus struct {
		Enabled  bool   `yaml:"enabled"`
		Port     int    `yaml:"port"`
		Path     string `yaml:"path"`
		Detailed bool   `yaml:"detailed"`
	} `yaml:"prometheus"`
	Radius radius.Config `yaml:"radius"`

	// Processor selects the backend: "api" (default) or "script".
	Processor string        `yaml:"processor"`
	Api       api.Config    `yaml:"api"`
	Script    script.Config `yaml:"script"`

	Profiler struct {
		Port    int  `yaml:"port"`
		Enabled bool `yaml:"enabled"`
	} `yaml:"profiler"`
}

// envVarPattern matches ${VAR} and ${VAR:-default}.
var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// Load reads the YAML config after substituting environment variables. Like in
// shell, the default is used when VAR is unset or empty; ${VAR} without a
// default is required, so the server never starts with a silently empty secret.
func Load(path string) (Configuration, error) {
	var conf Configuration
	data, err := os.ReadFile(path)
	if err != nil {
		return conf, err
	}
	var missing []string
	expanded := envVarPattern.ReplaceAllStringFunc(string(data), func(match string) string {
		groups := envVarPattern.FindStringSubmatch(match)
		if val := os.Getenv(groups[1]); val != "" {
			return val
		}
		if groups[2] != "" {
			return groups[3]
		}
		missing = append(missing, groups[1])
		return match
	})
	if len(missing) > 0 {
		return conf, fmt.Errorf("required environment variables not set: %v", strings.Join(missing, ", "))
	}
	err = yaml.Unmarshal([]byte(expanded), &conf)
	return conf, err
}
