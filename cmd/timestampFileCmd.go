package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"

	bbntypes "github.com/babylonchain/babylon/types"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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

		fundedTxOutputIdx, err := cmd.Flags().GetUint32(FlagFundedTxOutputIdx)
		if err != nil {
			return fmt.Errorf("failed to parse flag %s: %w", FlagFundedTxOutputIdx, err)
		}

		feeSatoshiPerByte, err := cmd.Flags().GetInt64(FlagFeeSatoshiPerByte)
		if err != nil {
			return fmt.Errorf("failed to parse flag %s: %w", FlagFeeSatoshiPerByte, err)
		}

		timestampOutput, err := CreateTimestampTx(fundedTxHex, inputFilePath, pubKeyHexStr, fundedTxOutputIdx, feeSatoshiPerByte)
		if err != nil {
			return fmt.Errorf("failed to create timestamping tx: %w", err)
		}

		PrintRespJSON(timestampOutput)
		return nil
	},
}

func CreateTimestampTx(fundedTxHex, filePath, pubKeyHexStr string, fundedTxOutputIdx uint32, feeSatoshiPerByte int64) (*TimestampFileOutput, error) {
	txOutFileHash, fileHash, err := txOutTimestampFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to create tx out with filepath %s: %w", filePath, err)
	}

	taprootPkScript, err := deriveTaprootPkScript(pubKeyHexStr)
	if err != nil {
		return nil, fmt.Errorf("unable to create pay-to-taproot output key pk script: %w", err)
	}

	fundedTx, _, err := newBTCTxFromHex(fundedTxHex)
	if err != nil {
		return nil, fmt.Errorf("unable parse BTC Tx %s: %w", fundedTxHex, err)
	}
	fundedTxHash := fundedTx.TxHash()
	fundedTxOutPoint := wire.NewOutPoint(&fundedTxHash, fundedTxOutputIdx)
	txOutputAsInput := wire.NewTxIn(fundedTxOutPoint, nil, nil)

	// TODO: refactory fee calc
	totalIn := sumValues(fundedTx.TxOut[fundedTxOutputIdx])

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(txOutputAsInput)

	txOutPk := wire.NewTxOut(0, taprootPkScript)
	bytesInTx := int64(tx.SerializeSize() + txOutPk.SerializeSize() + txOutFileHash.SerializeSize())

	totalFeeInSatoshi := (feeSatoshiPerByte * bytesInTx) + 2000 // cover?
	if totalIn < totalFeeInSatoshi {
		return nil, fmt.Errorf("total tx in: %d, fee: %d. Not enough to cover fees", totalIn, totalFeeInSatoshi)
	}
	txOutPk.Value = totalIn - totalFeeInSatoshi

	tx.AddTxOut(txOutPk)
	tx.AddTxOut(txOutFileHash)

	txHex, err := SerializeBTCTxToHex(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize timestamping tx: %w", err)
	}

	return &TimestampFileOutput{
		TimestampTx: txHex,
		PkTapRoot:   hex.EncodeToString(taprootPkScript),
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

func CreateTimestampAcc(amountToSendStr, pubKeyHexStr string) (*TimestampAcc, error) {
	amountToSend, err := strconv.ParseInt(amountToSendStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid amount %s: %w", amountToSendStr, err)
	}

	valueToSend, err := parseBtcAmount(amountToSend)
	if err != nil {
		return nil, err
	}

	taprootPkScript, err := deriveTaprootPkScript(pubKeyHexStr)
	if err != nil {
		return nil, fmt.Errorf("unable to create pay-to-taproot output key pk script: %w", err)
	}

	tx := wire.NewMsgTx(2)
	tx.AddTxOut(wire.NewTxOut(int64(valueToSend), taprootPkScript))

	txHex, err := SerializeBTCTxToHex(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize timestamping tx: %w", err)
	}

	return &TimestampAcc{
		AccTx:      txHex,
		TaprootAcc: hex.EncodeToString(taprootPkScript),
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
