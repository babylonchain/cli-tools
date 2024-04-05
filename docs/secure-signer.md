# Design of secure covenant signing system

## Context

In phase-1 mainnet, un-bonding transactions needs to be signed by covenant committee to become sendable to BTC. In later phases, covenant emulator program will need to sign both slashing and un-bonding transactions.  This makes covenant committee key handling a critical element of the whole Babylon system.

If majority of covenant keys would be stolen, then attacker could either collaborate with staker to withdraw the stake while putting blame on covenant committee member whose keys have been stolen, or he could trick staker to sign some transactions stealing his funds.

If majority of covenant keys would be lost, for phase-1 it means that users would not be able to un-bond, for phase-2 it means no new accepted delegations.

## Requirements

Requirements for secure signer:

1. signer should be highly available. This is needed as either in phase-1 or phase-2 signing requests can arrive any time
2. private key of signer should be encrypted when stored on disk. This is need to ensure that even if machine with private key will be compromised private key won’t leak.
3. it should be easy to create backup-up of private key. There should exists few backups of private key in case disk with the one in use will be wiped. Restoring signer from backup should be easy.
4. signer should be able to sign BTC transactions. This requirement forces signer to known how to properly sign BTC transactions

## Required reading

Following design will be based on following documents:

https://github.com/bitcoin/bitcoin/blob/master/doc/managing-wallets.md

https://github.com/bitcoin/bitcoin/blob/master/doc/offline-signing-tutorial.md

https://github.com/lightningnetwork/lnd/blob/master/docs/remote-signing.md


## High level overview

![diagram](/docs/diagram.png)


## Details

### Connection between Signing server and Bitcoin instance

Only component open to the internat is Signing Server which listens for signing requests.

Bitcoind instance in diagram must have all the p2p connections disabled and doesn’t need to have a blockchain copy. It should allow only one connection from signing server.

Bitcoind instance should have rpc-server enabled. Ways of securing this json-rpc connection are nicely described in https://github.com/bitcoin/bitcoin/blob/master/doc/JSON-RPC-interface.md#security

### Signing JSON-RPC method

To create signature signing server will be using https://developer.bitcoin.org/reference/rpc/walletprocesspsbt.html#walletprocesspsbt bitcoind endpoint.

Minimal data required to create valid psbt to sign transaction spending taproot input are:

1. output being spent
2. public key corresponding to private key which should sign given transaction. It should be 33bytes compressed format
3. control block required to spend given output. It contains: Internal public key, proof of inclusion of script in given taproot output, and version of the taproot leaf
4. whole script from the script path being used

### Wallet operations required to create and manage wallet with covenant key

To create encrypted wallet:

`$ bitcoin-cli -named createwallet wallet_name="wallet-01" passphrase="passphrase"`

To backup a wallet:

`$ bitcoin-cli -rpcwallet="wallet-01" backupwallet /home/node01/Backups/backup-01.dat`

To restore wallet from backup:

`$ bitcoin-cli restorewallet "restored-wallet" /home/node01/Backups/backup-01.dat`

### Creation of Covenant private/public key

After creation of encrypted wallet call:

`bitcoin-cli -rpcwallet=<wallet_name> getnewaddress`

This will generate new Bitcoin address (by default p2wpkh)  and new public key corresponding to his address.

Next call:

`bitcoin-cli -rpcwallet=<wallet_name> getaddressinfo "addressFromStep1"`

Response (https://developer.bitcoin.org/reference/rpc/getaddressinfo.html ) will contain pubkey field which contains hex encoded public key. This key can become covenant public key.

### Passphrase managment

Signing psbt through bitcoind encrypted wallet requires that the wallet is unlocked. This can be done through wallet passphrase command: - https://developer.bitcoin.org/reference/rpc/walletpassphrase.html

This command essentially decrypts private key and reads it into memory, so it is available for signing.

If attacker would get into possession of passphrase, he would be able to decrypt covenant member private key. This makes passphrase critical place in whole system.

There is spectrum of possibilities with different trade offs and security assumptions how to deal with this problem:

Most extreme version: bitcoind instance runs on server managed in locally in somebody server and only one person knows this passphrase. Just before unbonding pipeline runs, this person unlock wallet for an hour.

mild version: we also expose walletpassphrase endpoint through secured and encrypted channel, we have separate service which unlock wallet just before signing is needed.

more mild version: we unlock the wallet for whole lifecycle of bitcoind signer. This makes bitcoind signer a target for memory exfiltration attacks.
