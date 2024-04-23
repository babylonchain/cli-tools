# CLI-TOOLS

Set of CLI tools to run as Batch jobs on phase-1 main net

# Build
```
make all
```

# Example

## create-phase1-staking-tx
```
 ./build/cli-tools create-phase1-staking-tx --magic-bytes 62627434 \
--staker-pk 57349e985e742d5131e1e2b227b5170f6350ac2e2feb72254fcc25b3cee21a18 \
--staking-amount 1000000 \
--staking-time 21 \
--covenant-committee-pks ffeaec52a9b407b355ef6967a7ffc15fd6c3fe07de2844d61550475e7a5233e5 \
--covenant-committee-pks a5c60c2188e833d39d0fa798ab3f69aa12ed3dd2f3bad659effa252782de3c31 \
--covenant-committee-pks 59d3532148a597a2d05c0395bf5f7176044b1cd312f37701a9b4d0aad70bc5a4 \
--covenant-committee-pks 57349e985e742d5131e1e2b227b5170f6350ac2e2feb72254fcc25b3cee21a18 \
--covenant-committee-pks c8ccb03c379e452f10c81232b41a1ca8b63d0baf8387e57d302c987e5abb8527 \
--covenant-quorum 3 \
--network regtest \
--finality-provider-pk 03d5a0bb72d71993e435d6c5a70e2aa4db500a62cfaae33c56050deefee64ec0 | jq .staking_tx_hex
```

## create-phase1-unbonding-request
```
./build/cli-tools create-phase1-unbonding-request --magic-bytes 62627434 \
--unbonding-fee 1000000 \
--unbonding-time 21 \
--staking-tx-hex d7e7838a41874e5eaab50d79f3757bd6b7c8fba7f09dcc4cd506ea58cea90d33 \
--staker-wallet-rpc-user rpcuser \
--staker-wallet-rpc-pass rpcpass \
--staker-wallet-passphrase walletpass \
--staker-wallet-address-host localhost:18443 \
--covenant-committee-pks ffeaec52a9b407b355ef6967a7ffc15fd6c3fe07de2844d61550475e7a5233e5 \
--covenant-committee-pks a5c60c2188e833d39d0fa798ab3f69aa12ed3dd2f3bad659effa252782de3c31 \
--covenant-committee-pks 59d3532148a597a2d05c0395bf5f7176044b1cd312f37701a9b4d0aad70bc5a4 \
--covenant-committee-pks 57349e985e742d5131e1e2b227b5170f6350ac2e2feb72254fcc25b3cee21a18 \
--covenant-committee-pks c8ccb03c379e452f10c81232b41a1ca8b63d0baf8387e57d302c987e5abb8527 \
--covenant-quorum 3 \
--network regtest
```