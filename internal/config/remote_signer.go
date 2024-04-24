package config

import (
	"fmt"
	"time"
)

const (
	defaultHost    = "127.0.0.1"
	defaultPort    = 9791
	defaultTimeout = 10 * time.Second
)

type RemoteSignerConfig struct {
	Host    string        `mapstructure:"host"`
	Port    int           `mapstructure:"port"`
	Timeout time.Duration `mapstructure:"timeout"`
}

func (c *RemoteSignerConfig) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("empty host")
	}

	// verify 1 <= Port <= 65535
	if c.Port > 65535 || c.Port < 1 {
		return fmt.Errorf("invalid port %d", c.Port)
	}

	if c.Timeout <= 0 {
		return fmt.Errorf("timeout %d should be positive", c.Timeout)
	}

	return nil
}

func (c *RemoteSignerConfig) GetSignerUrl() string {
	return fmt.Sprintf("http://%s:%d", c.Host, c.Port)
}

func DefaultRemoteSignerConfig() *RemoteSignerConfig {
	return &RemoteSignerConfig{
		Host:    defaultHost,
		Port:    defaultPort,
		Timeout: defaultTimeout,
	}
}
