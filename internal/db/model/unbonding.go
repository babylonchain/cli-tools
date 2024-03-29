package model

import "go.mongodb.org/mongo-driver/bson/primitive"

// TODO Double check with staking-api-service
const (
	UnbondingCollection   = "unbonding_queue"
	UnbondingInitialState = "INSERTED"
)

type UnbondingState string

const (
	Inserted          UnbondingState = "INSERTED"
	Send              UnbondingState = "SEND"
	InputAlreadySpent UnbondingState = "INPUT_ALREADY_SPENT"
	Failed            UnbondingState = "FAILED"
)

// StakerPk           *btcec.PublicKey
// FinalityProviderPk *btcec.PublicKey
// StakingTime        uint16
// StakingAmount      btcutil.Amount

type UnbondingDocument struct {
	ID                 primitive.ObjectID `bson:"_id"`
	UnbondingTxHashHex string             `bson:"unbonding_tx_hash_hex"`
	UnbondingTxHex     string             `bson:"unbonding_tx_hex"`
	UnbondingTxSigHex  string             `bson:"unbonding_tx_sig_hex"`
	StakerPkHex        string             `bson:"staker_pk_hex"`
	FinalityPkHex      string             `bson:"finality_pk_hex"`
	StakingTime        uint64             `bson:"staking_time"`
	StakingAmount      uint64             `bson:"staking_amount"`
	// TODO: Staking pkscript is not necessary here as we can derive it from other
	// staking data + covenant_params. Although maybe it would be worth to have it
	// here to double check everything is ok
	State UnbondingState `bson:"state"`
}
