package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the agent configuration
type Config struct {
	Agent        AgentConfig        `yaml:"agent"`
	ControlPlane ControlPlaneConfig `yaml:"control_plane"`
	TLS          TLSConfig          `yaml:"tls"`
	Metrics      MetricsConfig      `yaml:"metrics"`
	Logging      LoggingConfig      `yaml:"logging"`
	Executor     ExecutorConfig     `yaml:"executor"`
}

type AgentConfig struct {
	ID     string            `yaml:"id"`
	Token  string            `yaml:"token"` // Auth token
	Name   string            `yaml:"name"`
	Labels map[string]string `yaml:"labels"`
}

type ControlPlaneConfig struct {
	Address              string        `yaml:"address"`
	Timeout              time.Duration `yaml:"timeout"`
	ReconnectInterval    time.Duration `yaml:"reconnect_interval"`
	MaxReconnectAttempts int           `yaml:"max_reconnect_attempts"`
}

type TLSConfig struct {
	Enabled            bool   `yaml:"enabled"`
	CACert             string `yaml:"ca_cert"`
	Cert               string `yaml:"cert"`
	Key                string `yaml:"key"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	UseSystemCerts     bool   `yaml:"use_system_certs"` // true when connecting via Cloudflare Tunnel (no mTLS)
}

type MetricsConfig struct {
	Enabled  bool           `yaml:"enabled"`
	Interval time.Duration  `yaml:"interval"`
	Collect  MetricsCollect `yaml:"collect"`
}

type MetricsCollect struct {
	CPU     bool `yaml:"cpu"`
	Memory  bool `yaml:"memory"`
	Disk    bool `yaml:"disk"`
	Network bool `yaml:"network"`
	Load    bool `yaml:"load"`
}

type LoggingConfig struct {
	Level                string `yaml:"level"`
	Format               string `yaml:"format"`
	File                 string `yaml:"file"`
	StreamToControlPlane bool   `yaml:"stream_to_control_plane"`
}

type ExecutorConfig struct {
	Shell           string        `yaml:"shell"`
	DefaultTimeout  time.Duration `yaml:"default_timeout"`
	AllowedCommands []string      `yaml:"allowed_commands"`
	BlockedCommands []string      `yaml:"blocked_commands"`
}

// Load reads and parses the configuration file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	cfg.setDefaults()

	return cfg, nil
}

func (c *Config) setDefaults() {
	if c.ControlPlane.Timeout == 0 {
		c.ControlPlane.Timeout = 30 * time.Second
	}
	if c.ControlPlane.ReconnectInterval == 0 {
		c.ControlPlane.ReconnectInterval = 5 * time.Second
	}
	if c.Metrics.Interval == 0 {
		c.Metrics.Interval = 10 * time.Second
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "text"
	}
	if c.Executor.Shell == "" {
		c.Executor.Shell = "/bin/bash"
	}
	if c.Executor.DefaultTimeout == 0 {
		c.Executor.DefaultTimeout = 5 * time.Minute
	}
}

// LoadOrCreate tries to load config from file, or creates a default one
func LoadOrCreate(path string) (*Config, error) {
	// Try to load existing config
	if _, err := os.Stat(path); err == nil {
		return Load(path)
	}

	// File doesn't exist, return a default config
	cfg := CreateDefault()
	return cfg, nil
}

// CreateDefault creates a config with sensible defaults
func CreateDefault() *Config {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "agent"
	}

	cfg := &Config{
		Agent: AgentConfig{
			ID:     "",
			Token:  "",
			Name:   hostname,
			Labels: map[string]string{},
		},
		ControlPlane: ControlPlaneConfig{
			Address:              "localhost:9443",
			Timeout:              30 * time.Second,
			ReconnectInterval:    5 * time.Second,
			MaxReconnectAttempts: 0,
		},
		TLS: TLSConfig{
			Enabled:            false,
			InsecureSkipVerify: false,
		},
		Metrics: MetricsConfig{
			Enabled:  true,
			Interval: 10 * time.Second,
			Collect: MetricsCollect{
				CPU:     true,
				Memory:  true,
				Disk:    true,
				Network: true,
				Load:    true,
			},
		},
		Logging: LoggingConfig{
			Level:                "info",
			Format:               "text",
			File:                 "/var/log/cloudnan-agent.log",
			StreamToControlPlane: true,
		},
		Executor: ExecutorConfig{
			Shell:           "/bin/bash",
			DefaultTimeout:  5 * time.Minute,
			AllowedCommands: []string{},
			BlockedCommands: []string{
				"rm -rf /",
				"rm -rf /*",
				"mkfs",
				":(){ :|:& };:",     // fork bomb
				"> /dev/sda",         // disk wipe
				"dd if=/dev/zero",    // disk wipe
				"chmod -R 777 /",     // permission bomb
				"chown -R",
			},
		},
	}

	return cfg
}

// Save writes the config to a file
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Create directory if not exists
	dir := path[:len(path)-len("/agent.yaml")]
	if dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
