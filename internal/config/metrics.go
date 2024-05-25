package config

import (
	"fmt"
	"net"
)

const (
	defaultMetricsPort = 2112
	defaultMetricsHost = "127.0.0.1"
)

// MetricsConfig defines the server's basic configuration
type MetricsConfig struct {
	Enabled bool   `long:"enabled" description:"Enable reporting metrics"`
	Host    string `long:"host" description:"IP of the Prometheus server"`
	Port    int    `long:"port" description:"Port of the Prometheus server"`
}

func (cfg *MetricsConfig) Validate() error {
	if cfg.Port < 0 || cfg.Port > 65535 {
		return fmt.Errorf("invalid port: %d", cfg.Port)
	}

	ip := net.ParseIP(cfg.Host)
	if ip == nil {
		return fmt.Errorf("invalid host: %v", cfg.Host)
	}

	return nil
}

func (cfg *MetricsConfig) Address() (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d", cfg.Host, cfg.Port), nil
}

func DefaultMetricsConfig() *MetricsConfig {
	return &MetricsConfig{
		Enabled: false,
		Port:    defaultMetricsPort,
		Host:    defaultMetricsHost,
	}
}
