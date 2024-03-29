package services

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/babylonchain/cli-tools/internal/db"
	"github.com/babylonchain/cli-tools/internal/db/model"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func NewBTCTxFromBytes(txBytes []byte) (*wire.MsgTx, error) {
	var msgTx wire.MsgTx
	rbuf := bytes.NewReader(txBytes)
	if err := msgTx.Deserialize(rbuf); err != nil {
		return nil, err
	}

	return &msgTx, nil
}

func NewBTCTxFromHex(txHex string) (*wire.MsgTx, []byte, error) {
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, nil, err
	}

	parsed, err := NewBTCTxFromBytes(txBytes)

	if err != nil {
		return nil, nil, err
	}

	return parsed, txBytes, nil
}

func SerializeBTCTx(tx *wire.MsgTx) ([]byte, error) {
	var txBuf bytes.Buffer
	if err := tx.Serialize(&txBuf); err != nil {
		return nil, err
	}
	return txBuf.Bytes(), nil
}

func SerializeBTCTxToHex(tx *wire.MsgTx) (string, error) {
	bytes, err := SerializeBTCTx(tx)

	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil

}

func pubKeyFromString(hexString string) (*btcec.PublicKey, error) {
	bytes, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, err
	}

	key, err := schnorr.ParsePubKey(bytes)

	if err != nil {
		return nil, err
	}

	return key, nil
}

type PersistentUnbondingStorage struct {
	client *db.Database
}

func NewPersistentUnbondingStorage(
	client *db.Database,
) *PersistentUnbondingStorage {
	return &PersistentUnbondingStorage{
		client: client,
	}
}

func documentToData(d *model.UnbondingDocument) (*UnbondingTxData, error) {
	tx, _, err := NewBTCTxFromHex(d.UnbondingTxHex)
	if err != nil {
		return nil, err
	}

	unbondingTxHash, err := chainhash.NewHashFromStr(d.UnbondingTxHashHex)

	if err != nil {
		return nil, err
	}

	sigBytes, err := hex.DecodeString(d.UnbondingTxSigHex)
	if err != nil {
		return nil, err
	}

	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return nil, err
	}

	stakerPk, err := pubKeyFromString(d.StakerPkHex)
	if err != nil {
		return nil, err
	}

	fpPk, err := pubKeyFromString(d.FinalityPkHex)
	if err != nil {
		return nil, err
	}

	// TODO: Check if there are better types at mongo level
	stakingValue := btcutil.Amount(int64(d.StakingAmount))
	stakingTime := uint16(d.StakingTime)

	return NewUnbondingTxData(tx, unbondingTxHash, sig, &StakingInfo{
		StakerPk:           stakerPk,
		FinalityProviderPk: fpPk,
		StakingTime:        stakingTime,
		StakingAmount:      stakingValue,
	}), nil
}

func (s *PersistentUnbondingStorage) AddTxWithSignature(
	ctx context.Context,
	tx *wire.MsgTx,
	sig *schnorr.Signature,
	info *StakingInfo) error {
	txHex, err := SerializeBTCTxToHex(tx)
	if err != nil {
		return err
	}

	txHash := tx.TxHash().String()

	sigBytes := sig.Serialize()
	sigHex := hex.EncodeToString(sigBytes)

	stakerPkHex := pubKeyToString(info.StakerPk)
	fpPkHex := pubKeyToString(info.FinalityProviderPk)

	err = s.client.SaveUnbondingDocument(
		ctx,
		txHash,
		txHex,
		sigHex,
		stakerPkHex,
		fpPkHex,
		uint64(info.StakingTime),
		uint64(info.StakingAmount),
	)

	if err != nil {
		return err
	}
	return nil
}

func (s *PersistentUnbondingStorage) GetNotProcessedUnbondingTransactions() ([]*UnbondingTxData, error) {
	docs, err := s.client.FindNewUnbondingDocuments(context.Background())
	if err != nil {
		return nil, err
	}

	var res []*UnbondingTxData
	for _, doc := range docs {
		data, err := documentToData(&doc)
		if err != nil {
			return nil, err
		}
		res = append(res, data)
	}

	return res, nil
}

func (s *PersistentUnbondingStorage) SetUnbondingTransactionProcessed(utx *UnbondingTxData) error {
	txHash := utx.UnbondingTransactionHash.String()
	return s.client.SetUnbondingDocumentSend(context.Background(), txHash)
}

func (s *PersistentUnbondingStorage) SetUnbondingTransactionProcessingFailed(utx *UnbondingTxData) error {
	txHash := utx.UnbondingTransactionHash.String()
	return s.client.SetUnbondingDocumentFailed(context.Background(), txHash)
}
