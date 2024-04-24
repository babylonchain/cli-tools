package services

import (
	"context"
	"time"

	"github.com/babylonchain/covenant-signer/signerservice"

	"github.com/babylonchain/cli-tools/internal/config"
)

type RemoteSigner struct {
	url     string
	timeout time.Duration
}

func NewRemoteSigner(cfg *config.RemoteSignerConfig) (*RemoteSigner, error) {
	// TODO we should be able to ping the remote signer
	return &RemoteSigner{
		url:     cfg.GetSignerUrl(),
		timeout: cfg.Timeout,
	}, nil
}

func (rs *RemoteSigner) SignUnbondingTransaction(req *SignRequest) (*PubKeySigPair, error) {
	sig, err := signerservice.RequestCovenantSignaure(
		context.Background(),
		rs.url,
		rs.timeout,
		req.UnbondingTransaction,
		req.SignerPubKey,
		req.UnbondingScript,
	)

	if err != nil {
		return nil, err
	}

	return &PubKeySigPair{
		Signature: sig,
		PubKey:    req.SignerPubKey,
	}, nil
}
