package config

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	defaultUrl     = "http://127.0.0.1:9791"
	defaultTimeout = 10 * time.Second
)

var (
	privKey, _        = btcec.NewPrivateKey()
	defaultUrls       = []string{defaultUrl}
	defaultPublicKeys = []string{hex.EncodeToString(privKey.PubKey().SerializeCompressed())}
)

type RemoteSignerConfig struct {
	Urls       []string      `mapstructure:"urls"`
	PublicKeys []string      `mapstructure:"public_keys"`
	Timeout    time.Duration `mapstructure:"timeout"`
}

type ParsedRemoteSignerConfig struct {
	Urls       []*url.URL
	PublicKeys []*btcec.PublicKey
	Timeout    time.Duration
}

func (c *RemoteSignerConfig) Parse() (*ParsedRemoteSignerConfig, error) {
	nUrls := len(c.Urls)
	if nUrls == 0 {
		return nil, fmt.Errorf("must have at least one url")
	}

	nPubKyes := len(c.PublicKeys)
	if nPubKyes == 0 {
		return nil, fmt.Errorf("must have at least one public key")
	}

	if nUrls != nPubKyes {
		return nil, fmt.Errorf("the number of urls %d must match the number of public keys %d", nUrls, nPubKyes)
	}

	urls := make([]*url.URL, nUrls)
	publicKeys := make([]*btcec.PublicKey, nPubKyes)
	for i, urlStr := range c.Urls {
		parsedUrl, err := url.Parse(urlStr)
		if err != nil {
			return nil, fmt.Errorf("invalid url %s: %w", urlStr, err)
		}
		urls[i] = parsedUrl

		pkBytes, err := hex.DecodeString(c.PublicKeys[i])
		if err != nil {
			return nil, fmt.Errorf("invalid public key %s: %w", c.PublicKeys[i], err)
		}

		pk, err := btcec.ParsePubKey(pkBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid public key %s: %w", c.PublicKeys[i], err)
		}

		publicKeys[i] = pk
	}

	if c.Timeout <= 0 {
		return nil, fmt.Errorf("timeout %d should be positive", c.Timeout)
	}

	return &ParsedRemoteSignerConfig{
		Urls:       urls,
		PublicKeys: publicKeys,
		Timeout:    c.Timeout,
	}, nil
}

func (pc *ParsedRemoteSignerConfig) GetPubKeyToUrlMap() (map[string]string, error) {
	nUrls := len(pc.Urls)
	if nUrls == 0 {
		return nil, fmt.Errorf("must have at least one url")
	}

	nPubKyes := len(pc.PublicKeys)
	if nPubKyes == 0 {
		return nil, fmt.Errorf("must have at least one public key")
	}

	if nUrls != nPubKyes {
		return nil, fmt.Errorf("the number of urls %d must match the number of public keys %d", nUrls, nPubKyes)
	}

	mapPkToUrl := make(map[string]string)
	for i, u := range pc.Urls {
		pkStr := hex.EncodeToString(pc.PublicKeys[i].SerializeCompressed())
		mapPkToUrl[pkStr] = u.String()
	}

	return mapPkToUrl, nil
}

func DefaultRemoteSignerConfig() *RemoteSignerConfig {
	return &RemoteSignerConfig{
		Urls:       defaultUrls,
		PublicKeys: defaultPublicKeys,
		Timeout:    defaultTimeout,
	}
}
