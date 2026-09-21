package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/meklis/all-ok-radius-server/api"
	"github.com/meklis/all-ok-radius-server/logger"
	"github.com/meklis/all-ok-radius-server/script"
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
		Enabled                 bool              `yaml:"enabled"`
		Port                    int               `yaml:"port"`
		Path                    string            `yaml:"path"`
		RecalcEstabConnsTimeout time.Duration     `yaml:"recalc_estab_timeout"`
		LiveRecalc              bool              `yaml:"live_recalc"`
		Labels                  map[string]string `yaml:"static_labels"`
		Detailed                bool              `yaml:"detailed"`
	} `yaml:"prometheus"`
	Radius struct {
		ListenAddr string `yaml:"listen_addr"`
		Secret     string `yaml:"secret"`
		// ReadBufferSize - размер SO_RCVBUF в байтах. 0 - системный default
		// (обычно net.core.rmem_default, на busy-системах маловат под всплески).
		ReadBufferSize int `yaml:"read_buffer_size"`
	} `yaml:"radius"`

	// processor: "api" (по умолчанию) или "script" - выбирает, какой из блоков ниже используется
	Processor string        `yaml:"processor"`
	Api       api.ApiConfig `yaml:"api"`
	Script    script.Config `yaml:"script"`

	Profiler struct {
		Port    int  `yaml:"port"`
		Enabled bool `yaml:"enabled"`
	} `yaml:"profiler"`
}

// envVarPattern матчит ${VAR} и ${VAR:-default} в конфиге.
var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// expandEnvVars подставляет переменные окружения в конфиг. ${VAR:-default} использует
// default, если VAR не задан или пуст (как в shell). ${VAR} без default обязателен -
// если такая переменная не задана, возвращается ошибка со списком всех отсутствующих,
// чтобы не запускать сервер с "тихо" незаполненными обязательными полями (secret, url и т.п.)
func expandEnvVars(s string) (string, error) {
	var missing []string
	result := envVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		groups := envVarPattern.FindStringSubmatch(match)
		name, hasDefault, def := groups[1], groups[2] != "", groups[3]
		if val, ok := os.LookupEnv(name); ok && val != "" {
			return val
		}
		if hasDefault {
			return def
		}
		missing = append(missing, name)
		return match
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("required environment variables not set: %v", strings.Join(missing, ", "))
	}
	return result, nil
}

func LoadConfig(path string, Config *Configuration) error {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	yamlConfig, err := expandEnvVars(string(bytes))
	if err != nil {
		return err
	}
	err = yaml.Unmarshal([]byte(yamlConfig), &Config)
	fmt.Printf(`Loaded configuration from %v with env readed:
%v
`, path, yamlConfig)
	if err != nil {
		return err
	}
	return nil
}

func ConfigureLogger(conf *Configuration) *logger.Logger {
	if conf.Logger.Console.Enabled {
		color := 0
		if conf.Logger.Console.EnableColor {
			color = 1
		}
		lg, _ := logger.New("radius", color, os.Stdout)
		lg.SetLogLevel(logger.LogLevel(conf.Logger.Console.LogLevel))
		if !conf.Logger.Console.PrintFile {
			lg.SetFormat("#%{id} %{time} > %{level} %{message}")
		} else {
			lg.SetFormat("#%{id} %{time} (%{filename}:%{line}) > %{level} %{message}")
		}
		return lg
	} else {
		lg, _ := logger.New("no_log", 0, os.DevNull)
		return lg
	}
}
