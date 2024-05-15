//go:build e2e
// +build e2e

package e2etest

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	staking "github.com/babylonchain/babylon/btcstaking"
	signerbtccli "github.com/babylonchain/covenant-signer/btcclient"
	signercfg "github.com/babylonchain/covenant-signer/config"
	"github.com/babylonchain/covenant-signer/signerapp"
	"github.com/babylonchain/covenant-signer/signerservice"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/babylonchain/cli-tools/cmd"
	"github.com/babylonchain/cli-tools/internal/btcclient"
	"github.com/babylonchain/cli-tools/internal/config"
	"github.com/babylonchain/cli-tools/internal/db"
	"github.com/babylonchain/cli-tools/internal/db/model"
	"github.com/babylonchain/cli-tools/internal/logger"
	"github.com/babylonchain/cli-tools/internal/services"
	"github.com/babylonchain/cli-tools/itest/containers"
)

const (
	passphrase     = "pass"
	FundWalletName = "test-wallet"
)

var (
	netParams = &chaincfg.RegressionNetParams
)

type TestManager struct {
	t                   *testing.T
	bitcoindHandler     *BitcoindTestHandler
	walletPass          string
	btcClient           *btcclient.BtcClient
	covenantPublicKeys  []*btcec.PublicKey
	covenantQuorum      uint32
	finalityProviderKey *btcec.PrivateKey
	stakerAddress       btcutil.Address
	stakerPrivKey       *btcec.PrivateKey
	stakerPubKey        *btcec.PublicKey
	magicBytes          []byte
	pipeLineConfig      *config.Config
	pipeLine            *services.UnbondingPipeline
	testStoreController *services.PersistentUnbondingStorage
	signingServer       *signerservice.SigningServer
	parameters          *services.ParsedGlobalParams
}

type stakingData struct {
	stakingAmount  btcutil.Amount
	stakingTime    uint16
	stakingFeeRate btcutil.Amount
	unbondingTime  uint16
	unbondingFee   btcutil.Amount
}

func defaultStakingData() *stakingData {
	return &stakingData{
		stakingAmount:  btcutil.Amount(100000),
		stakingTime:    10000,
		stakingFeeRate: btcutil.Amount(5000), // feeRatePerKb
		// TODO: Move those to global params
		unbondingTime: 100,
		unbondingFee:  btcutil.Amount(10000),
	}
}

func (d *stakingData) unbondingAmount() btcutil.Amount {
	return d.stakingAmount - d.unbondingFee
}

// PurgeAllCollections drops all collections in the specified database.
func PurgeAllCollections(ctx context.Context, client *mongo.Client, databaseName string) error {
	database := client.Database(databaseName)
	collections, err := database.ListCollectionNames(ctx, bson.D{{}})
	if err != nil {
		return err
	}

	for _, collection := range collections {
		if err := database.Collection(collection).Drop(ctx); err != nil {
			return err
		}
	}
	return nil
}

func StartManager(
	t *testing.T,
	numMatureOutputsInWallet uint32,
	runMongodb bool,
) *TestManager {
	logger := logger.DefaultLogger()
	m, err := containers.NewManager()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = m.ClearResources()
	})

	h := NewBitcoindHandler(t, m)
	h.Start()

	appConfig := config.DefaultConfig()

	if runMongodb {
		_, err = m.RunMongoDbResource()
		require.NoError(t, err)

		appConfig.Db.Address = fmt.Sprintf("mongodb://%s", m.MongoHost())
	}

	// Give some time to launch mongo and bitcoind
	time.Sleep(2 * time.Second)

	_ = h.CreateWallet(FundWalletName, passphrase)
	// only outputs which are 100 deep are mature
	_ = h.GenerateBlocks(int(numMatureOutputsInWallet) + 100)

	appConfig.Btc.Host = "127.0.0.1:18443"
	appConfig.Btc.User = "user"
	appConfig.Btc.Pass = "pass"
	appConfig.Btc.Network = netParams.Name

	magicBytes := []byte{0x0, 0x1, 0x2, 0x3}
	signerCfg, signerGlobalParams, signingServer := startSigningServer(t, magicBytes)

	appConfig.Signer = *signerCfg

	var gp = services.ParsedGlobalParams{}

	ver := services.ParsedVersionedGlobalParams{
		Version:        0,
		CovenantPks:    signerGlobalParams.Versions[0].CovenantPks,
		CovenantQuorum: signerGlobalParams.Versions[0].CovenantQuorum,
		Tag:            magicBytes,
	}

	gp.Versions = append(gp.Versions, &ver)

	// Client for testing purposes
	client, err := btcclient.NewBtcClient(&appConfig.Btc)
	require.NoError(t, err)

	outputs, err := client.ListOutputs(true)
	require.NoError(t, err)
	require.Len(t, outputs, int(numMatureOutputsInWallet))

	// easiest way to get address controlled by wallet is to retrive address from one
	// of the outputs
	output := outputs[0]
	walletAddress, err := btcutil.DecodeAddress(output.Address, netParams)
	require.NoError(t, err)

	err = client.UnlockWallet(60*60*60, passphrase)
	require.NoError(t, err)
	stakerPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	fpKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pipeLine, err := services.NewUnbondingPipelineFromConfig(
		logger,
		appConfig,
		&gp,
	)
	require.NoError(t, err)

	tm := &TestManager{
		t:                   t,
		bitcoindHandler:     h,
		walletPass:          passphrase,
		btcClient:           client,
		covenantPublicKeys:  signerGlobalParams.Versions[0].CovenantPks,
		covenantQuorum:      signerGlobalParams.Versions[0].CovenantQuorum,
		finalityProviderKey: fpKey,
		stakerAddress:       walletAddress,
		stakerPrivKey:       stakerPrivKey,
		stakerPubKey:        stakerPrivKey.PubKey(),
		magicBytes:          []byte{0x0, 0x1, 0x2, 0x3},
		pipeLineConfig:      appConfig,
		pipeLine:            pipeLine,
		testStoreController: nil,
		signingServer:       signingServer,
		parameters:          &gp,
	}

	if runMongodb {
		testDbConnection, err := db.New(context.TODO(), appConfig.Db.DbName, appConfig.Db.Address)
		require.NoError(t, err)

		storeController := services.NewPersistentUnbondingStorage(testDbConnection)
		tm.testStoreController = storeController
	}

	return tm
}

func startSigningServer(
	t *testing.T,
	magicBytes []byte,
) (*config.RemoteSignerConfig, *signerapp.ParsedGlobalParams, *signerservice.SigningServer) {
	appConfig := signercfg.DefaultConfig()
	appConfig.BtcNodeConfig.Host = "127.0.0.1:18443"
	appConfig.BtcNodeConfig.User = "user"
	appConfig.BtcNodeConfig.Pass = "pass"
	appConfig.BtcNodeConfig.Network = netParams.Name

	fakeParsedConfig, err := appConfig.Parse()
	require.NoError(t, err)
	// Client for testing purposes
	client, err := signerbtccli.NewBtcClient(fakeParsedConfig.BtcNodeConfig)
	require.NoError(t, err)

	// Unlock wallet for all tests 60min
	err = client.UnlockWallet(60*60*60, passphrase)
	require.NoError(t, err)

	// generate 2 local covenants
	covPublicKeys := make([]*btcec.PublicKey, 0)
	covAddress1, err := client.RpcClient.GetNewAddress("covenant1")
	require.NoError(t, err)
	info1, err := client.RpcClient.GetAddressInfo(covAddress1.EncodeAddress())
	require.NoError(t, err)
	covenantPubKeyBytes1, err := hex.DecodeString(*info1.PubKey)
	require.NoError(t, err)
	localCovenantKey1, err := btcec.ParsePubKey(covenantPubKeyBytes1)
	require.NoError(t, err)
	covPublicKeys = append(covPublicKeys, localCovenantKey1)

	covAddress2, err := client.RpcClient.GetNewAddress("covenant2")
	require.NoError(t, err)
	info2, err := client.RpcClient.GetAddressInfo(covAddress2.EncodeAddress())
	require.NoError(t, err)
	covenantPubKeyBytes2, err := hex.DecodeString(*info2.PubKey)
	require.NoError(t, err)
	localCovenantKey2, err := btcec.ParsePubKey(covenantPubKeyBytes2)
	require.NoError(t, err)
	covPublicKeys = append(covPublicKeys, localCovenantKey2)

	quorum := uint32(2)
	host := "127.0.0.1"
	port := 9791
	covenantPksStr := []string{
		hex.EncodeToString(localCovenantKey1.SerializeCompressed()),
		hex.EncodeToString(localCovenantKey2.SerializeCompressed()),
	}
	urlsStr := []string{
		fmt.Sprintf("http://%s@%s:%d", covenantPksStr[0], host, port),
		fmt.Sprintf("http://%s@%s:%d", covenantPksStr[1], host, port),
	}
	signerCfg := &config.RemoteSignerConfig{
		Urls:           urlsStr,
		TimeoutSeconds: 10,
	}

	appConfig.Server.Host = host
	appConfig.Server.Port = port
	parsedconfig, err := appConfig.Parse()
	require.NoError(t, err)

	// In e2e test we are using the same node for signing as for indexing functionalities
	chainInfo := signerapp.NewBitcoindChainInfo(client)
	signer := signerapp.NewPsbtSigner(client)

	signerGlobalParams := signerapp.ParsedGlobalParams{
		Versions: []*signerapp.ParsedVersionedGlobalParams{
			{
				Version:           0,
				ActivationHeight:  0,
				StakingCap:        btcutil.Amount(100000000000),
				Tag:               magicBytes,
				CovenantQuorum:    quorum,
				CovenantPks:       []*btcec.PublicKey{localCovenantKey1, localCovenantKey2},
				ConfirmationDepth: 1,
				UnbondingTime:     100,
				UnbondingFee:      btcutil.Amount(10000),
				MinStakingTime:    1,
				MaxStakingTime:    math.MaxUint16,
				MinStakingAmount:  btcutil.Amount(1),
				MaxStakingAmount:  btcutil.Amount(100000000000),
			},
		},
	}

	app := signerapp.NewSignerApp(
		signer,
		chainInfo,
		&signerGlobalParams,
		netParams,
	)

	server, err := signerservice.New(
		context.Background(),
		parsedconfig,
		app,
	)

	require.NoError(t, err)

	go func() {
		_ = server.Start()
	}()

	// Give some time to launch server
	time.Sleep(3 * time.Second)

	t.Cleanup(func() {
		_ = server.Stop(context.TODO())
	})

	return signerCfg, &signerGlobalParams, server
}

type stakingTxSigInfo struct {
	stakingTxHash *chainhash.Hash
	stakingOutput *wire.TxOut
}

func (tm *TestManager) sendStakingTxToBtc(d *stakingData) *stakingTxSigInfo {
	info, err := staking.BuildV0IdentifiableStakingOutputs(
		tm.magicBytes,
		tm.stakerPubKey,
		tm.finalityProviderKey.PubKey(),
		tm.covenantPublicKeys,
		tm.covenantQuorum,
		d.stakingTime,
		d.stakingAmount,
		netParams,
	)
	require.NoError(tm.t, err)

	err = tm.btcClient.UnlockWallet(20, tm.walletPass)
	require.NoError(tm.t, err)
	// staking output will always have index 0
	tx, err := tm.btcClient.CreateAndSignTx(
		[]*wire.TxOut{info.StakingOutput, info.OpReturnOutput},
		d.stakingFeeRate,
		tm.stakerAddress,
	)
	require.NoError(tm.t, err)

	hash, err := tm.btcClient.SendTx(tx)
	require.NoError(tm.t, err)
	// generate blocks to make sure tx will be included into chain
	_ = tm.bitcoindHandler.GenerateBlocks(2)
	return &stakingTxSigInfo{
		stakingTxHash: hash,
		stakingOutput: info.StakingOutput,
	}
}

type unbondingTxWithMetadata struct {
	unbondingTx *wire.MsgTx
	signature   *schnorr.Signature
}

func (tm *TestManager) createUnbondingTxAndSignByStaker(
	si *stakingTxSigInfo,
	d *stakingData,
) *unbondingTxWithMetadata {

	info, err := staking.BuildV0IdentifiableStakingOutputs(
		tm.magicBytes,
		tm.stakerPubKey,
		tm.finalityProviderKey.PubKey(),
		tm.covenantPublicKeys,
		tm.covenantQuorum,
		d.stakingTime,
		d.stakingAmount,
		netParams,
	)
	require.NoError(tm.t, err)

	unbondingPathInfo, err := info.UnbondingPathSpendInfo()
	require.NoError(tm.t, err)

	unbondingInfo, err := staking.BuildUnbondingInfo(
		tm.stakerPubKey,
		[]*btcec.PublicKey{tm.finalityProviderKey.PubKey()},
		tm.covenantPublicKeys,
		tm.covenantQuorum,
		d.unbondingTime,
		d.unbondingAmount(),
		netParams,
	)
	require.NoError(tm.t, err)

	unbondingTx := wire.NewMsgTx(2)
	unbondingTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(si.stakingTxHash, 0), nil, nil))
	unbondingTx.AddTxOut(unbondingInfo.UnbondingOutput)

	unbondingTxSignature, err := staking.SignTxWithOneScriptSpendInputFromScript(
		unbondingTx,
		si.stakingOutput,
		tm.stakerPrivKey,
		unbondingPathInfo.RevealedLeaf.Script,
	)
	require.NoError(tm.t, err)

	return &unbondingTxWithMetadata{
		unbondingTx: unbondingTx,
		signature:   unbondingTxSignature,
	}
}

func (tm *TestManager) createStakingInfo(d *stakingData) *services.StakingInfo {
	return &services.StakingInfo{
		StakerPk:           tm.stakerPubKey,
		FinalityProviderPk: tm.finalityProviderKey.PubKey(),
		StakingTimelock:    d.stakingTime,
		StakingAmount:      d.stakingAmount,
	}
}

func (tm *TestManager) createNUnbondingTransactions(n int, d *stakingData) ([]*unbondingTxWithMetadata, []*wire.MsgTx) {
	var infos []*stakingTxSigInfo
	var sendStakingTransactions []*wire.MsgTx

	for i := 0; i < n; i++ {
		sInfo := tm.sendStakingTxToBtc(d)
		conf, status, err := tm.btcClient.TxDetails(sInfo.stakingTxHash, sInfo.stakingOutput.PkScript)
		require.NoError(tm.t, err)
		require.Equal(tm.t, btcclient.TxInChain, status)
		infos = append(infos, sInfo)
		sendStakingTransactions = append(sendStakingTransactions, conf.Tx)
	}

	var unbondingTxs []*unbondingTxWithMetadata
	for _, i := range infos {
		info := i
		ubs := tm.createUnbondingTxAndSignByStaker(
			info,
			d,
		)
		unbondingTxs = append(unbondingTxs, ubs)
	}

	return unbondingTxs, sendStakingTransactions
}

func TestBtcTimestamp(t *testing.T) {
	tm := StartManager(t, 10, false)
	btcd := tm.bitcoindHandler

	wName := "btc-file-timestamping"
	resp := btcd.CreateWallet(wName, passphrase)
	require.Equal(t, wName, resp.Name)

	newAddr := btcd.GetNewAddress(wName)
	require.NotEmpty(t, newAddr)
	fmt.Printf("\n New Addr %s\n", newAddr.String())

	btcd.SendToAddress(FundWalletName, newAddr.String(), "25")
	btcd.GenerateBlocks(5)
	unspentTxt := btcd.ListUnspent(wName)
	fmt.Printf("\nunspentTxt: %s", unspentTxt)

	addrInfo := btcd.GetAddressInfo(wName, newAddr.String())
	require.Equal(t, newAddr.String(), addrInfo.Address)
	require.NotNil(t, addrInfo.PubKey)

	pubKeyStr := *addrInfo.PubKey
	require.Greater(t, len(pubKeyStr), 2)
	pubKeyHex := pubKeyStr[2:]

	amountToTaprootPk := int64(15000000)
	timestampAcc, err := cmd.CreateTimestampAcc(strconv.FormatInt(amountToTaprootPk, 10), pubKeyHex)
	require.NoError(t, err)

	fundedTx := btcd.FundRawTx(wName, timestampAcc.AccTx)
	fundedTxHex, err := cmd.SerializeBTCTxToHex(fundedTx.Transaction)
	require.NoError(t, err)

	btcd.WalletPassphrase(wName, passphrase, "70")
	signedTxResult := btcd.SignRawTxWithWallet(wName, fundedTxHex)

	btcd.SendRawTx(wName, signedTxResult.Hex)
	btcd.GenerateBlocks(5)

	currentPath, err := os.Getwd()
	require.NoError(t, err)
	modFilePath := filepath.Join(currentPath, "../go.mod")
	fmt.Printf("\nmodFilePath: %s", modFilePath)
	fmt.Printf("\nStart Create Timestamp TX")

	fundedTxOutputIdx := uint32(1) // is one, because when funding the tx it adds a new txout
	for idx, txOut := range fundedTx.Transaction.TxOut {
		if txOut.Value == amountToTaprootPk {
			fundedTxOutputIdx = uint32(idx)
			break
		}
	}

	feeSatoshiPerByte := int64(5)
	timestampFileOutput, err := cmd.CreateTimestampTx(signedTxResult.Hex, modFilePath, pubKeyHex, fundedTxOutputIdx, feeSatoshiPerByte)
	require.NoError(t, err)
	require.NotNil(t, timestampFileOutput)

	fundedTx = btcd.FundRawTx(wName, timestampFileOutput.TimestampTx)
	fundedTxHex, err = cmd.SerializeBTCTxToHex(fundedTx.Transaction)
	require.NoError(t, err)

	signedTxResult = btcd.SignRawTxWithWallet(wName, fundedTxHex)
	txHashTimestampFile := btcd.SendRawTx(wName, signedTxResult.Hex)
	btcd.GenerateBlocks(5)

	fmt.Printf("\ntxHashTimestampFile: %s", txHashTimestampFile)
	txResult := btcd.GetTransaction(txHashTimestampFile)
	fmt.Printf("\ntxResult: %+v", txResult)
	// cmd.CreateTimestampTx()
	// amountToSend := int64(2500)
	// txHash, err := tm.btcClient.TransferSatoshiTo(amountToSend, 10, newAddr, FundWalletName)
	// require.NoError(t, err)
	// require.NotNil(t, txHash)

	// m.btcClient.CheckTxOutSpendable(
	// 	[]*wire.TxOut{
	// 		wire.NewTxOut(amountToSend, payToAddrScript)
	// 	},

	// )

	// E2E test
	// generate new addr
	// get pub key
	// crate-timestamp-account -> acc_tx_hex
	// funded -> acc_tx_hex_funded
	// signwithwallet -> tx_hex_signed
	// sendrawtx
	// create-timestamp-transaction [previous-timestamp-tx == acc_tx_hex_funded] [file-path] 836e9fc730ff37de48f2ff3a76b3c2380fbabaf66d9e50754d86b2a2e2952156
	// txOut1 = txscript.NullDataScript(fileHash)

	// txOut2= value as (originalOutput - fee) fee is calculated prob from btcd
	// txOut2= taproot pk will continue to have funds...
	// tapRootKey := txscript.ComputeTaprootKeyNoScript(schnorrPk)
	// taprootPkScript, err := txscript.PayToTaprootScript(tapRootKey)

	// Need to attach input to the new transaction to create
}

func TestSendingFreshTransactions(t *testing.T) {
	m := StartManager(t, 10, true)
	d := defaultStakingData()
	numUnbondingTxs := 10

	// 1. Generate all unbonding transactions
	ubts, stakingTransactions := m.createNUnbondingTransactions(numUnbondingTxs, d)

	// 2. Add all unbonding transactions to store
	for i, u := range ubts {
		ubs := u
		err := m.testStoreController.AddTxWithSignature(
			context.Background(),
			ubs.unbondingTx,
			ubs.signature,
			m.createStakingInfo(d),
			&services.StakingTransactionData{
				StakingTransaction: stakingTransactions[i],
				// we always use 0 index for staking output in e2e tests
				StakingOutputIdx: 0,
			},
		)
		require.NoError(t, err)
	}

	// 3. Check store is not empty
	txRequireProcessingBefore, err := m.testStoreController.GetNotProcessedUnbondingTransactions(context.TODO())
	require.NoError(t, err)
	require.Len(t, txRequireProcessingBefore, numUnbondingTxs)

	alreadySend, err := m.testStoreController.GetSendUnbondingTransactions(context.TODO())
	require.NoError(t, err)
	require.Len(t, alreadySend, 0)

	// 4. Run pipeline
	err = m.pipeLine.ProcessNewTransactions(context.Background())
	require.NoError(t, err)

	// 5. Generate few block to make sure transactions are included in btc
	_ = m.bitcoindHandler.GenerateBlocks(5)

	// 6. Check all included in btc chain
	for _, u := range ubts {
		ubs := u
		unbondingTxHash := ubs.unbondingTx.TxHash()
		_, status, err := m.btcClient.TxDetails(&unbondingTxHash, ubs.unbondingTx.TxOut[0].PkScript)
		require.NoError(t, err)
		require.Equal(t, btcclient.TxInChain, status)
	}

	// 7. Check there is no more transactions to process, and all previous transactions
	// are considered send
	txRequireProcessingAfter, err := m.testStoreController.GetNotProcessedUnbondingTransactions(context.TODO())
	require.NoError(t, err)
	require.Len(t, txRequireProcessingAfter, 0)

	sendTransactions, err := m.testStoreController.GetSendUnbondingTransactions(context.TODO())
	require.NoError(t, err)
	require.Len(t, sendTransactions, numUnbondingTxs)
}

func (tm *TestManager) updateSchnorSigInDb(newSig *schnorr.Signature, txHash *chainhash.Hash) {
	db, err := db.New(context.TODO(), tm.pipeLineConfig.Db.DbName, tm.pipeLineConfig.Db.Address)
	require.NoError(tm.t, err)
	txHashHex := txHash.String()
	client := db.Client.Database(db.DbName).Collection(model.UnbondingCollection)
	sigHex := hex.EncodeToString(newSig.Serialize())
	filter := bson.M{"unbonding_tx_hash_hex": txHashHex}
	update := bson.M{"$set": bson.M{"unbonding_tx_sig_hex": sigHex}}
	_, err = client.UpdateOne(context.TODO(), filter, update)
	require.NoError(tm.t, err)
}

func TestHandlingCriticalError(t *testing.T) {
	m := StartManager(t, 10, true)
	d := defaultStakingData()

	unb, stk := m.createNUnbondingTransactions(1, d)

	unbondingTx := unb[0]
	stakingTx := stk[0]

	invalidSchnorrSigBytes := unbondingTx.signature.Serialize()
	// change one byte in signature to make it invalid
	invalidSchnorrSigBytes[63] = invalidSchnorrSigBytes[63] + 1
	invalidSchnorrSig, err := schnorr.ParseSignature(invalidSchnorrSigBytes)
	require.NoError(t, err)

	// 1. Add unbonding transaction with invalid signature, so it will fail when sending
	err = m.testStoreController.AddTxWithSignature(
		context.Background(),
		unbondingTx.unbondingTx,
		invalidSchnorrSig,
		m.createStakingInfo(d),
		&services.StakingTransactionData{
			StakingTransaction: stakingTx,
			// we always use 0 index for staking output in e2e tests
			StakingOutputIdx: 0,
		},
	)
	require.NoError(t, err)

	alreadySend, err := m.testStoreController.GetSendUnbondingTransactions(context.TODO())
	require.NoError(t, err)
	require.Len(t, alreadySend, 0)

	// 2. Run pipeline
	err = m.pipeLine.ProcessNewTransactions(context.Background())
	require.Error(t, err)
	// With invalid signature in db, signers will refuse to sign it, which should end
	// with critical error
	require.True(t, errors.Is(err, services.ErrCriticalError))

	// TODO:Find a way to simulate bitcoind not accepting transaction
}
