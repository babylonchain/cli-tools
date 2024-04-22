package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/spf13/viper"
)

type Config struct {
	Db     DbConfig           `mapstructure:"db-config"`
	Btc    BtcConfig          `mapstructure:"btc-config"`
	Params ParamsConfig       `mapstructure:"params-config"`
	Signer RemoteSignerConfig `mapstructure:"remote-signer-config"`
}

func DefaultConfig() *Config {
	return &Config{
		Db:     *DefaultDBConfig(),
		Btc:    *DefaultBtcConfig(),
		Params: *DefaultParamsConfig(),
		Signer: *DefaultRemoteSignerConfig(),
	}
}

func (cfg *Config) Validate() error {
	if err := cfg.Db.Validate(); err != nil {
		return fmt.Errorf("invalid db config: %w", err)
	}

	if err := cfg.Signer.Validate(); err != nil {
		return fmt.Errorf("invalid remote signer config: %w", err)
	}

	return nil
}

const defaultConfigTemplate = `# This is a TOML config file.
# For more information, see https://github.com/toml-lang/toml

[db-config]
# The network chain ID
db-name = "{{ .Db.DbName }}"
# The keyring's backend, where the keys are stored (os|file|kwallet|pass|test|memory)
address = "{{ .Db.Address }}"

[btc-config]
# Btc node host
host = "{{ .Btc.Host }}"
# Btc node user
user = "{{ .Btc.User }}"
# Btc node password
pass = "{{ .Btc.Pass }}"
# Btc network (testnet3|mainnet|regtest|simnet|signet)
network = "{{ .Btc.Network }}"

[params-config]
# The list of covenant public keys
covenant_public_keys = [{{ range .Params.CovenantPublicKeys }}{{ printf "%q, " . }}{{end}}]

# The quorum of the covenants required to sign the transaction
covenant_quorum = {{ .Params.CovenantQuorum }}

[remote-signer-config]
# The host of the remote signing server
host = {{ .Signer.Host }}
# The port of the remote signing server
port = {{ .Signer.Port }}
# The timeout of each request to the remote signing server
timeout = {{ .Signer.Timeout }}
`

var configTemplate *template.Template

func init() {
	var err error
	tmpl := template.New("configFileTemplate").Funcs(template.FuncMap{
		"StringsJoin": strings.Join,
	})
	if configTemplate, err = tmpl.Parse(defaultConfigTemplate); err != nil {
		panic(err)
	}
}

func writeConfigToFile(configFilePath string, config *Config) error {
	var buffer bytes.Buffer

	if err := configTemplate.Execute(&buffer, config); err != nil {
		panic(err)
	}

	return os.WriteFile(configFilePath, buffer.Bytes(), 0o600)
}

func WriteConfigToFile(pathToConfFile string, conf *Config) error {
	dirPath, _ := filepath.Split(pathToConfFile)

	if _, err := os.Stat(pathToConfFile); os.IsNotExist(err) {
		if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
			return fmt.Errorf("couldn't make config: %v", err)
		}

		if err := writeConfigToFile(pathToConfFile, conf); err != nil {
			return fmt.Errorf("could config to the file: %v", err)
		}
	}
	return nil
}

func fileNameWithoutExtension(fileName string) string {
	return strings.TrimSuffix(fileName, filepath.Ext(fileName))
}

func GetConfig(pathToConfFile string) (*Config, error) {
	dir, file := filepath.Split(pathToConfFile)
	configName := fileNameWithoutExtension(file)
	viper.SetConfigName(configName)
	viper.AddConfigPath(dir)
	viper.SetConfigType("toml")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	conf := DefaultConfig()
	if err := viper.Unmarshal(conf); err != nil {
		return nil, err
	}

	return conf, nil
}
