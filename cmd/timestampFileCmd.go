package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"

	bbntypes "github.com/babylonchain/babylon/types"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/spf13/cobra"
)

const (
	FlagFundedTxOutputIdx = "tx-funded-output-idx"
	FlagFeeSatoshiPerByte = "fee-satoshi-per-byte"
)

type TimestampAcc struct {
	AccTx      string `json:"acc_tx_hex"`
	TaprootAcc string `json:"taproot_acc_hex"`
}

type TimestampFileOutput struct {
	TimestampTx string `json:"timestamp_tx_hex"`
	PkTapRoot   string `json:"pk_tap_root"`
	FileHash    string `json:"file_hash"`
}

func init() {
	_ = btcTimestampFileCmd.Flags().Uint32(FlagFundedTxOutputIdx, 0, "the idx of the output to spend in the txs")
	_ = btcTimestampFileCmd.Flags().Uint32(FlagFeeSatoshiPerByte, 5, "the amount of satoshi to calculate as fee per byte")

	rootCmd.AddCommand(btcCreateTimestampAcc)
	rootCmd.AddCommand(btcTimestampFileCmd)
}

var btcTimestampFileCmd = &cobra.Command{
	Use:     "create-timestamp-transaction [previous-timestamp-tx] [file-path] [pub-key-hex]",
	Example: `cli-tools btc-timestamp-file [funded-tx-hex] ./path/to/file/to/timestamp 836e9fc730ff37de48f2ff3a76b3c2380fbabaf66d9e50754d86b2a2e2952156`,
	Short:   "Creates a timestamp btc transaction by hashing the file input.",
	Long: `Creates a timestamp BTC transaction with 2 outputs.
	The first output is the nullDataScript of the file hash, as the file hash
	being the sha256 of the input file path. This first output is the timestamp of the file.
	The second output is the taproot derived from the pubkey with ComputeTaprootKeyNoScript
	and PayToTaprootScript with the value as ({funded-tx-output} - {fees}). The second
	output is needed to continue to have spendable funds to the taproot pk.`,
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		fundedTxHex, inputFilePath, pubKeyHexStr := args[0], args[1], args[2]

		// fundedTxOutputIdx, err := cmd.Flags().GetUint32(FlagFundedTxOutputIdx)
		// if err != nil {
		// 	return fmt.Errorf("failed to parse flag %s: %w", FlagFundedTxOutputIdx, err)
		// }

		// feeSatoshiPerByte, err := cmd.Flags().GetInt64(FlagFeeSatoshiPerByte)
		// if err != nil {
		// 	return fmt.Errorf("failed to parse flag %s: %w", FlagFeeSatoshiPerByte, err)
		// }

		timestampOutput, err := CreateTimestampTx(fundedTxHex, inputFilePath, pubKeyHexStr, 200)
		if err != nil {
			return fmt.Errorf("failed to create timestamping tx: %w", err)
		}

		PrintRespJSON(timestampOutput)
		return nil
	},
}

func outputIndexForPkScript(pkScript []byte, tx *wire.MsgTx) (int, error) {
	for i, txOut := range tx.TxOut {
		if bytes.Equal(txOut.PkScript, pkScript) {
			return i, nil
		}
	}
	return -1, fmt.Errorf("unable to find output index for pk script")
}

func CreateTimestampTx(
	fundedTxHex, filePath, changeAddress string,
	fee int64,
) (*TimestampFileOutput, error) {
	txOutFileHash, fileHash, err := txOutTimestampFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to create tx out with filepath %s: %w", filePath, err)
	}

	fundingTx, _, err := newBTCTxFromHex(fundedTxHex)
	if err != nil {
		return nil, fmt.Errorf("unable parse BTC Tx %s: %w", fundedTxHex, err)
	}

	address, err := btcutil.DecodeAddress(changeAddress, &chaincfg.RegressionNetParams)

	if err != nil {
		return nil, fmt.Errorf("invalid address %s: %w", changeAddress, err)
	}

	addressPkScript, err := txscript.PayToAddrScript(address)

	if err != nil {
		return nil, fmt.Errorf("unable to create pk script from address %s: %w", changeAddress, err)
	}

	if !txscript.IsPayToWitnessPubKeyHash(addressPkScript) {
		return nil, fmt.Errorf("address %s is not a pay-to-witness-pubkey-hash", changeAddress)
	}

	fundingOutputIdx, err := outputIndexForPkScript(addressPkScript, fundingTx)
	if err != nil {
		return nil, fmt.Errorf("unable to find output index for pk script: %w", err)
	}
	fundingTxHash := fundingTx.TxHash()
	fundingInput := wire.NewTxIn(
		wire.NewOutPoint(&fundingTxHash, uint32(fundingOutputIdx)),
		nil,
		nil,
	)

	changeOutput := wire.NewTxOut(
		fundingTx.TxOut[fundingOutputIdx].Value-fee,
		addressPkScript,
	)

	timestampTx := wire.NewMsgTx(2)
	timestampTx.AddTxIn(fundingInput)
	timestampTx.AddTxOut(changeOutput)
	timestampTx.AddTxOut(txOutFileHash)

	txHex, err := SerializeBTCTxToHex(timestampTx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize timestamping tx: %w", err)
	}

	return &TimestampFileOutput{
		TimestampTx: txHex,
		PkTapRoot:   "",
		FileHash:    hex.EncodeToString(fileHash),
	}, nil
}

func sumValues(txs ...*wire.TxOut) (total int64) {
	for _, tx := range txs {
		total += tx.Value
	}
	return total
}

func deriveTaprootPkScript(pubKeyHexStr string) ([]byte, error) {
	pubkey, err := bbntypes.NewBIP340PubKeyFromHex(pubKeyHexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid public key %s: %w", pubKeyHexStr, err)
	}

	schnorrPk, err := schnorr.ParsePubKey(*pubkey)
	if err != nil {
		return nil, fmt.Errorf("unable to parse public key %s: %w", pubKeyHexStr, err)
	}

	tapRootKey := txscript.ComputeTaprootKeyNoScript(schnorrPk)
	return txscript.PayToTaprootScript(tapRootKey)
}

var btcCreateTimestampAcc = &cobra.Command{
	Use:     "create-timestamp-account [value] [pub-key-hex]",
	Example: `cli-tools create-timestamp-account 100000 836e9fc730ff37de48f2ff3a76b3c2380fbabaf66d9e50754d86b2a2e2952156`,
	Short: `Creates a timestamp btc account computed from the pub key by computing
the taproot key with no script (ComputeTaprootKeyNoScript) and send the [value]
amount to it.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		amountToSendStr, pubKeyHexStr := args[0], args[1]

		acc, err := CreateTimestampAcc(amountToSendStr, pubKeyHexStr)
		if err != nil {
			return fmt.Errorf("unable to create timestamp acc: %w", err)
		}

		PrintRespJSON(acc)
		return nil
	},
}

func CreateTimestampAcc(amountToSendStr, address string) (*TimestampAcc, error) {
	amountToSend, err := strconv.ParseInt(amountToSendStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid amount %s: %w", amountToSendStr, err)
	}

	valueToSend, err := parseBtcAmount(amountToSend)
	if err != nil {
		return nil, err
	}

	decodedAddress, err := btcutil.DecodeAddress(address, &chaincfg.RegressionNetParams)

	if err != nil {
		return nil, fmt.Errorf("invalid address %s: %w", address, err)
	}

	pkScript, err := txscript.PayToAddrScript(decodedAddress)

	if err != nil {
		return nil, fmt.Errorf("unable to create pk script from address %s: %w", address, err)
	}

	if !txscript.IsPayToWitnessPubKeyHash(pkScript) {
		return nil, fmt.Errorf("address %s is not a pay-to-witness-pubkey-hash", address)
	}

	tx := wire.NewMsgTx(2)
	tx.AddTxOut(wire.NewTxOut(int64(valueToSend), pkScript))

	txHex, err := SerializeBTCTxToHex(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize timestamping tx: %w", err)
	}

	return &TimestampAcc{
		AccTx: txHex,
		// TaprootAcc: hex.EncodeToString(taprootPkScript),
	}, nil
}

func txOutTimestampFile(filePath string) (txOut *wire.TxOut, fileHash []byte, err error) {
	fileHash, err = hashFromFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate hash from file %s: %w", filePath, err)
	}

	dataScript, err := txscript.NullDataScript(fileHash)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create op return with hash from file %s: %w", fileHash, err)
	}

	return wire.NewTxOut(0, dataScript), fileHash, nil
}

func hashFromFile(filePath string) ([]byte, error) {
	h := sha256.New()

	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open the file %s: %w", filePath, err)
	}
	defer f.Close()

	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
