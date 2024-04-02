package services

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// Minimal set of data necessary to sign unbonding transaction
type SignRequest struct {
	// Unbonding transaction which should be signed
	UnbondingTransaction *wire.MsgTx
	// Staking output which was used to fund unbonding transaction
	FundingOutput *wire.TxOut
	// Script of the path which should be execute - unbonding path
	UnbondingScript []byte
	// Public key of the signer
	SignerPubKey *btcec.PublicKey
}

func NewSignRequest(
	tx *wire.MsgTx,
	fundingOutput *wire.TxOut,
	script []byte,
	pubKey *btcec.PublicKey,
) *SignRequest {
	return &SignRequest{
		UnbondingTransaction: tx,
		FundingOutput:        fundingOutput,
		UnbondingScript:      script,
		SignerPubKey:         pubKey,
	}
}

type PubKeySigPair struct {
	Signature *schnorr.Signature
	PubKey    *btcec.PublicKey
}

type CovenantSigner interface {
	// This interface assumes that covenant signer has access to params and all necessary data
	SignUnbondingTransaction(req *SignRequest) (*PubKeySigPair, error)
}

type BtcSender interface {
	SendTx(tx *wire.MsgTx) (*chainhash.Hash, error)
}

type SystemParams struct {
	CovenantQuorum     uint32
	CovenantPublicKeys []*btcec.PublicKey
}

type ParamsRetriever interface {
	GetParams() (*SystemParams, error)
}

// TODO This data is necessary to recreate staking script tree, and create proof
// of inclusion when sending unbonding transaction. Defeine how it should be passed
// from api to unbodning pipeline and covenant signer
type StakingInfo struct {
	StakerPk           *btcec.PublicKey
	FinalityProviderPk *btcec.PublicKey
	StakingTime        uint16
	StakingAmount      btcutil.Amount
}

type UnbondingTxData struct {
	UnbondingTransaction     *wire.MsgTx
	UnbondingTransactionHash *chainhash.Hash
	UnbondingTransactionSig  *schnorr.Signature
	// TODO: For now we assume that staking info is part of db
	StakingInfo *StakingInfo
}

func NewUnbondingTxData(
	tx *wire.MsgTx,
	hash *chainhash.Hash,
	sig *schnorr.Signature,
	info *StakingInfo,
) *UnbondingTxData {
	return &UnbondingTxData{
		UnbondingTransaction:     tx,
		UnbondingTransactionHash: hash,
		UnbondingTransactionSig:  sig,
		StakingInfo:              info,
	}
}

type UnbondingStore interface {
	// TODO: For now it returns all not processed unbonding transactions but should:
	// 1. either return iterator over view of results
	// 2. or have limit argument to retrieve only N records
	// Interface Contract: results should be returned in the order they were added to the store
	GetNotProcessedUnbondingTransactions(ctx context.Context) ([]*UnbondingTxData, error)

	SetUnbondingTransactionProcessed(ctx context.Context, utx *UnbondingTxData) error

	SetUnbondingTransactionProcessingFailed(ctx context.Context, utx *UnbondingTxData) error
}
