package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	FlagTxFee = "tx-fee"
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
	btcTimestampFileCmd.Flags().Int64(FlagTxFee, 100, "unbonding fee")

	rootCmd.AddCommand(btcTimestampFileCmd)
	rootCmd.AddCommand(btcCreateTimestampAcc)
}

var btcTimestampFileCmd = &cobra.Command{
	Use:     "btc-timestamp-file [file-path] [pub-key-hex]",
	Example: `cli-tools btc-timestamp-file ./path/to/file/to/timestamp 836e9fc730ff37de48f2ff3a76b3c2380fbabaf66d9e50754d86b2a2e2952156`,
	Short:   "Creates a timestamp btc transaction by hashing the file input.",
	Long: `Creates a timestamp BTC transaction with 2 outputs.
	The first output is the taproot output which can be spend only by the
	keyspend path. The taproot output key is defined as the babylon secp256k1 pub key
	+ txscript.ComputeTaprootKeyNoScript(pubKey).
	The second output read the file received as argument, hash it with
	sha256 to have 32 byte hash with zero value.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		inputFilePath := args[0]
		if len(inputFilePath) == 0 {
			return errors.New("invalid argument, please provide a valid file path as input argument")
		}

		fileHash, err := hashFromFile(inputFilePath)
		if err != nil {
			return fmt.Errorf("failed to generate hash from file %s: %w", inputFilePath, err)
		}

		dataScript, err := txscript.NullDataScript(fileHash)
		if err != nil {
			return fmt.Errorf("failed to create op return with hash from file %s: %w", fileHash, err)
		}

		txOutFileHash := wire.NewTxOut(0, dataScript)

		pubKeyHex := args[1]
		pubkey, err := bbntypes.NewBIP340PubKeyFromHex(pubKeyHex)
		if err != nil {
			return fmt.Errorf("invalid public key %s: %w", pubKeyHex, err)
		}

		schnorrPk, err := schnorr.ParsePubKey(*pubkey)
		if err != nil {
			return fmt.Errorf("unable to parse public key %s: %w", pubKeyHex, err)
		}

		tapRootKey := txscript.ComputeTaprootKeyNoScript(schnorrPk)
		taprootPkScript, err := txscript.PayToTaprootScript(tapRootKey)
		if err != nil {
			return fmt.Errorf("unable to create pay-to-taproot output key pk script: %w", err)
		}

		txFee, err := parseBtcAmount(mustGetInt64Flag(cmd, FlagTxFee))
		if err != nil {
			return err
		}

		txPk := wire.NewTxOut(int64(txFee), taprootPkScript)

		tx := wire.NewMsgTx(2)
		tx.AddTxOut(txPk)
		tx.AddTxOut(txOutFileHash)

		txHex, err := serializeBTCTxToHex(tx)
		if err != nil {
			return fmt.Errorf("failed to serialize timestamping tx: %w", err)
		}

		PrintRespJSON(TimestampFileOutput{
			TimestampTx: txHex,
			PkTapRoot:   hex.EncodeToString(taprootPkScript),
			FileHash:    hex.EncodeToString(fileHash),
		})
		return nil
	},
}

var btcCreateTimestampAcc = &cobra.Command{
	Use:     "crate-timestamp-account [value] [pub-key-hex]",
	Example: `cli-tools crate-timestamp-account 100000 836e9fc730ff37de48f2ff3a76b3c2380fbabaf66d9e50754d86b2a2e2952156`,
	Short: `Creates a timestamp btc account computed from the pub key by computing
the taproot key with no script (ComputeTaprootKeyNoScript) and send the [value] 
amount to it.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		amountToSendStr := args[0]
		amountToSend, err := strconv.ParseInt(amountToSendStr, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid amount %s: %w", amountToSendStr, err)
		}

		pubKeyHex := args[1]
		pubkey, err := bbntypes.NewBIP340PubKeyFromHex(pubKeyHex)
		if err != nil {
			return fmt.Errorf("invalid public key %s: %w", pubKeyHex, err)
		}

		schnorrPk, err := schnorr.ParsePubKey(*pubkey)
		if err != nil {
			return fmt.Errorf("unable to parse public key %s: %w", pubKeyHex, err)
		}

		tapRootKey := txscript.ComputeTaprootKeyNoScript(schnorrPk)
		taprootPkScript, err := txscript.PayToTaprootScript(tapRootKey)
		if err != nil {
			return fmt.Errorf("unable to create pay-to-taproot output key pk script: %w", err)
		}

		valueToSend, err := parseBtcAmount(amountToSend)
		if err != nil {
			return err
		}

		txNewPk := wire.NewTxOut(int64(valueToSend), taprootPkScript)

		tx := wire.NewMsgTx(2)
		tx.AddTxOut(txNewPk)

		txHex, err := serializeBTCTxToHex(tx)
		if err != nil {
			return fmt.Errorf("failed to serialize timestamping tx: %w", err)
		}

		PrintRespJSON(TimestampAcc{
			AccTx:      txHex,
			TaprootAcc: hex.EncodeToString(taprootPkScript),
		})
		return nil
	},
}

func hashFromFile(inputFilePath string) ([]byte, error) {
	h := sha256.New()

	f, err := os.Open(inputFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open the file %s: %w", inputFilePath, err)
	}
	defer f.Close()

	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
