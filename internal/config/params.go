package config

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type ParamsConfig struct {
	CovenantPublicKeys []string `mapstructure:"covenant_public_keys"`
	CovenantQuorum     uint64   `mapstructure:"covenant_quorum"`
}

func DefaultParamsConfig() *ParamsConfig {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		panic(err)
	}

	encoded := hex.EncodeToString(schnorr.SerializePubKey(privKey.PubKey()))

	return &ParamsConfig{
		CovenantPublicKeys: []string{encoded},
		CovenantQuorum:     1,
	}
}

type ParsedParamsConfig struct {
	CovenantPublicKeys []*btcec.PublicKey
	CovenantQuorum     uint32
}

func (cfg *ParamsConfig) Parse() (*ParsedParamsConfig, error) {
	var covenantPublicKeys []*btcec.PublicKey

	for _, key := range cfg.CovenantPublicKeys {
		decoded, err := hex.DecodeString(key)
		if err != nil {
			return nil, err
		}

		pubKey, _ := btcec.ParsePubKey(decoded)
		covenantPublicKeys = append(covenantPublicKeys, pubKey)
	}

	if len(covenantPublicKeys) < int(cfg.CovenantQuorum) {
		return nil, fmt.Errorf("not enough private keys for the quorum")
	}

	return &ParsedParamsConfig{
		CovenantPublicKeys: covenantPublicKeys,
		CovenantQuorum:     uint32(cfg.CovenantQuorum),
	}, nil
}
