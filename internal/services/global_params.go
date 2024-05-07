package services

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"

	"github.com/babylonchain/babylon/btcstaking"
)

func checkPositive(value uint64) error {
	if value == 0 {
		return fmt.Errorf("value must be positive")
	}
	return nil
}

func parseTimeLockValue(timelock uint64) (uint16, error) {
	if timelock > math.MaxUint16 {
		return 0, fmt.Errorf("timelock value %d is too large. Max: %d", timelock, math.MaxUint16)
	}

	if err := checkPositive(timelock); err != nil {
		return 0, fmt.Errorf("invalid timelock value: %w", err)
	}

	return uint16(timelock), nil
}

func parseBtcValue(value uint64) (btcutil.Amount, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("value %d is too large. Max: %d", value, math.MaxInt64)
	}

	if err := checkPositive(value); err != nil {
		return 0, fmt.Errorf("invalid btc value value: %w", err)
	}
	// retrun amount in satoshis
	return btcutil.Amount(value), nil
}

func parseUint32(value uint64) (uint32, error) {
	if value > math.MaxUint32 {
		return 0, fmt.Errorf("value %d is too large. Max: %d", value, math.MaxUint32)
	}

	if err := checkPositive(value); err != nil {
		return 0, fmt.Errorf("invalid value: %w", err)
	}

	return uint32(value), nil
}

// parseCovenantPubKeyFromHex parses public key string to btc public key
// the input should be 33 bytes
func parseCovenantPubKeyFromHex(pkStr string) (*btcec.PublicKey, error) {
	pkBytes, err := hex.DecodeString(pkStr)
	if err != nil {
		return nil, err
	}

	pk, err := btcec.ParsePubKey(pkBytes)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

var _ ParamsRetriever = (*ParsedGlobalParams)(nil)

type VersionedGlobalParams struct {
	Version          uint64   `json:"version"`
	ActivationHeight uint64   `json:"activation_height"`
	StakingCap       uint64   `json:"staking_cap"`
	Tag              string   `json:"tag"`
	CovenantPks      []string `json:"covenant_pks"`
	CovenantQuorum   uint64   `json:"covenant_quorum"`
	UnbondingTime    uint64   `json:"unbonding_time"`
	UnbondingFee     uint64   `json:"unbonding_fee"`
	MaxStakingAmount uint64   `json:"max_staking_amount"`
	MinStakingAmount uint64   `json:"min_staking_amount"`
	MaxStakingTime   uint64   `json:"max_staking_time"`
	MinStakingTime   uint64   `json:"min_staking_time"`
}

type GlobalParams struct {
	Versions []*VersionedGlobalParams `json:"versions"`
}

type ParsedGlobalParams struct {
	Versions []*ParsedVersionedGlobalParams
}

type ParsedVersionedGlobalParams struct {
	Version          uint64
	ActivationHeight uint64
	StakingCap       btcutil.Amount
	Tag              []byte
	CovenantPks      []*btcec.PublicKey
	CovenantQuorum   uint32
	UnbondingTime    uint16
	UnbondingFee     btcutil.Amount
	MaxStakingAmount btcutil.Amount
	MinStakingAmount btcutil.Amount
	MaxStakingTime   uint16
	MinStakingTime   uint16
}

func NewGlobalParams(filePath string) (*ParsedGlobalParams, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var globalParams GlobalParams
	err = json.Unmarshal(data, &globalParams)
	if err != nil {
		return nil, err
	}

	parsedGlobalParams, err := ParseGlobalParams(&globalParams)

	if err != nil {
		return nil, err
	}

	return parsedGlobalParams, nil
}

func parseVersionedGlobalParams(p *VersionedGlobalParams) (*ParsedVersionedGlobalParams, error) {
	tag, err := hex.DecodeString(p.Tag)

	if err != nil {
		return nil, fmt.Errorf("invalid tag: %w", err)
	}

	if len(tag) != btcstaking.MagicBytesLen {
		return nil, fmt.Errorf("invalid tag length, expected %d, got %d", btcstaking.MagicBytesLen, len(p.Tag))
	}

	if len(p.CovenantPks) == 0 {
		return nil, fmt.Errorf("empty covenant public keys")
	}
	if p.CovenantQuorum > uint64(len(p.CovenantPks)) {
		return nil, fmt.Errorf("covenant quorum cannot be more than the amount of covenants")
	}

	quroum, err := parseUint32(p.CovenantQuorum)
	if err != nil {
		return nil, fmt.Errorf("invalid covenant quorum: %w", err)
	}

	var covenantKeys []*btcec.PublicKey
	for _, covPk := range p.CovenantPks {
		pk, err := parseCovenantPubKeyFromHex(covPk)
		if err != nil {
			return nil, fmt.Errorf("invalid covenant public key %s: %w", covPk, err)
		}

		covenantKeys = append(covenantKeys, pk)
	}

	maxStakingAmount, err := parseBtcValue(p.MaxStakingAmount)

	if err != nil {
		return nil, fmt.Errorf("invalid max_staking_amount: %w", err)
	}

	minStakingAmount, err := parseBtcValue(p.MinStakingAmount)

	if err != nil {
		return nil, fmt.Errorf("invalid min_staking_amount: %w", err)
	}

	if maxStakingAmount <= minStakingAmount {
		return nil, fmt.Errorf("max-staking-amount must be larger than min-staking-amount")
	}

	ubTime, err := parseTimeLockValue(p.UnbondingTime)
	if err != nil {
		return nil, fmt.Errorf("invalid unbonding_time: %w", err)
	}

	ubFee, err := parseBtcValue(p.UnbondingFee)
	if err != nil {
		return nil, fmt.Errorf("invalid unbonding_fee: %w", err)
	}

	maxStakingTime, err := parseTimeLockValue(p.MaxStakingTime)
	if err != nil {
		return nil, fmt.Errorf("invalid max_staking_time: %w", err)
	}

	minStakingTime, err := parseTimeLockValue(p.MinStakingTime)
	if err != nil {
		return nil, fmt.Errorf("invalid min_staking_time: %w", err)
	}

	// NOTE: Allow config when max-staking-time is equal to min-staking-time, as then
	// we can configure a fixed staking time.
	if maxStakingTime < minStakingTime {
		return nil, fmt.Errorf("max-staking-time must be larger or equalt min-staking-time")
	}

	stakingCap, err := parseBtcValue(p.StakingCap)
	if err != nil {
		return nil, fmt.Errorf("invalid staking_cap: %w", err)
	}

	return &ParsedVersionedGlobalParams{
		Version:          p.Version,
		ActivationHeight: p.ActivationHeight,
		StakingCap:       stakingCap,
		Tag:              tag,
		CovenantPks:      covenantKeys,
		CovenantQuorum:   quroum,
		UnbondingTime:    ubTime,
		UnbondingFee:     ubFee,
		MaxStakingAmount: maxStakingAmount,
		MinStakingAmount: minStakingAmount,
		MaxStakingTime:   maxStakingTime,
		MinStakingTime:   minStakingTime,
	}, nil
}

func ParseGlobalParams(p *GlobalParams) (*ParsedGlobalParams, error) {
	if len(p.Versions) == 0 {
		return nil, fmt.Errorf("global params must have at least one version")
	}
	var parsedVersions []*ParsedVersionedGlobalParams

	for _, v := range p.Versions {
		vCopy := v
		cv, err := parseVersionedGlobalParams(vCopy)

		if err != nil {
			return nil, fmt.Errorf("invalid params with version %d: %w", vCopy.Version, err)
		}

		// Check latest version
		if len(parsedVersions) > 0 {
			pv := parsedVersions[len(parsedVersions)-1]

			if cv.Version != pv.Version+1 {
				return nil, fmt.Errorf("invalid params with version %d. versions should be monotonically increasing by 1", cv.Version)
			}
			if cv.StakingCap < pv.StakingCap {
				return nil, fmt.Errorf("invalid params with version %d. staking cap cannot be decreased in later versions", cv.Version)
			}
			if cv.ActivationHeight < pv.ActivationHeight {
				return nil, fmt.Errorf("invalid params with version %d. activation height cannot be overlapping between earlier and later versions", cv.Version)
			}
		}

		parsedVersions = append(parsedVersions, cv)
	}

	return &ParsedGlobalParams{
		Versions: parsedVersions,
	}, nil
}

func (g *ParsedGlobalParams) getVersionedGlobalParamsByHeight(btcHeight uint64) *ParsedVersionedGlobalParams {
	// Iterate the list in reverse (i.e. decreasing ActivationHeight)
	// and identify the first element that has an activation height below
	// the specified BTC height.
	for i := len(g.Versions) - 1; i >= 0; i-- {
		paramsVersion := g.Versions[i]
		if paramsVersion.ActivationHeight <= btcHeight {
			return paramsVersion
		}
	}
	return nil
}

func (g *ParsedGlobalParams) ParamsByHeight(_ context.Context, height uint64) (*SystemParams, error) {
	versionedParams := g.getVersionedGlobalParamsByHeight(height)
	if versionedParams == nil {
		return nil, fmt.Errorf("no global params for height %d", height)
	}

	return &SystemParams{
		CovenantPublicKeys: versionedParams.CovenantPks,
		CovenantQuorum:     versionedParams.CovenantQuorum,
		MagicBytes:         versionedParams.Tag,
	}, nil
}
