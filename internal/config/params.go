package config

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
)

type UnsafeParamsConfig struct {
	CovenantPrivateKeys []string `mapstructure:"covenant_private_keys"`
	CovenantQuorum      uint64   `mapstructure:"covenant_quorum"`
}

func DefaultUnsafeParamsConfig() *UnsafeParamsConfig {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		panic(err)
	}

	encoded := hex.EncodeToString(privKey.Serialize())

	return &UnsafeParamsConfig{
		CovenantPrivateKeys: []string{encoded},
		CovenantQuorum:      1,
	}
}
