use crate::constants::{NETWORK_VERSION_TEMP, NETWORK_VERSION_V0, P2SH_PREPEND, TX_PREPEND};
use crate::crypto::sha3_256;
use crate::crypto::sign_ed25519::{self as sign, PublicKey, SecretKey};
use crate::primitives::asset::{Asset, DataAsset, TokenAmount};
use crate::primitives::druid::{DdeValues, DruidExpectation};
use crate::primitives::transaction::*;
use crate::script::lang::Script;
use crate::script::StackEntry;
use bincode::serialize;
use bytes::Bytes;
use std::collections::BTreeMap;

/// Builds an address for a P2SH transaction
///
/// ### Arguments
///
/// * `script` - Script to build address for
pub fn construct_p2sh_address(script: &Script) -> String {
    let script_bytes = Bytes::from(serialize(script).unwrap());
    let script_raw_h = sha3_256::digest(&script_bytes).to_vec();
    let mut hash = hex::encode(script_raw_h);

    hash.insert(0, P2SH_PREPEND as char);
    hash.truncate(32);

    hash
}

/// Builds an address from a public key and a specified network version
///
/// ### Arguments
///
/// * `pub_key` - A public key to build an address from
pub fn construct_address_for(pub_key: &PublicKey, address_version: Option<u64>) -> String {
    match address_version {
        Some(NETWORK_VERSION_V0) => construct_address_v0(pub_key),
        Some(NETWORK_VERSION_TEMP) => construct_address_temp(pub_key),
        _ => construct_address(pub_key),
    }
}

/// Builds an address from a public key
///
/// ### Arguments
///
/// * `pub_key` - A public key to build an address from
pub fn construct_address(pub_key: &PublicKey) -> String {
    let pub_key_hash = sha3_256::digest(pub_key.as_ref());
    hex::encode(pub_key_hash)
}

/// Builds an old (network version 0) address from a public key
///
/// ### Arguments
///
/// * `pub_key` - A public key to build an address from
fn construct_address_v0(pub_key: &PublicKey) -> String {
    let first_pubkey_bytes = {
        // We used sodiumoxide serialization before with a 64 bit length prefix.
        // Make clear what we are using as this was not intended.
        let mut v = vec![32, 0, 0, 0, 0, 0, 0, 0];
        v.extend_from_slice(pub_key.as_ref());
        v
    };
    let mut first_hash = sha3_256::digest(&first_pubkey_bytes).to_vec();

    first_hash.truncate(16);

    hex::encode(first_hash)
}

/// Builds an address from a public key using the
/// temporary address scheme present on the wallet
///
/// TODO: Depreciate after addresses retire
///
/// ### Arguments
///
/// * `pub_key` - A public key to build an address from
pub fn construct_address_temp(pub_key: &PublicKey) -> String {
    let base64_encoding = base64::encode(pub_key.as_ref());
    let hex_decoded = decode_base64_as_hex(&base64_encoding);
    let pub_key_hash = sha3_256::digest(&hex_decoded);
    hex::encode(pub_key_hash)
}

/// Decodes a base64 encoded string as hex, invalid character pairs are decoded up to the
/// first character. If the decoding up to the first character fails, a default value of 0
/// is used.
///
/// TODO: Depreciate after addresses retire
///
/// ### Arguments
///
/// * `s`   - Base64 encoded string
pub fn decode_base64_as_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .or_else(|_| u8::from_str_radix(&s[i..i + 1], 16))
                .unwrap_or_default()
        })
        .collect()
}

/// Constructs signable string for OutPoint
///
///
/// ### Arguments
///
/// * `out_point`   - OutPoint value
pub fn get_out_point_signable_string(out_point: &OutPoint) -> String {
    format!("{}-{}", out_point.n, out_point.t_hash)
}

/// Constructs signable hash for a TxIn
///
/// ### Arguments
///
/// * `previous_out`   - Previous transaction used as input
pub fn construct_tx_in_signable_hash(previous_out: &OutPoint) -> String {
    hex::encode(sha3_256::digest(
        get_out_point_signable_string(previous_out).as_bytes(),
    ))
}

/// Constructs signable string for an Asset
///
/// ### Arguments
///
/// * `asset`   - Asset to sign
pub fn get_asset_signable_string(asset: &Asset) -> String {
    match asset {
        Asset::Token(token_amount) => format!("Token:{}", token_amount.0),
        Asset::Data(data_asset) => format!(
            "Data:{}-{}",
            hex::encode(&data_asset.data),
            data_asset.amount
        ),
        Asset::Receipt(receipt) => format!("Receipt:{}", receipt.amount),
    }
}

/// Constructs signable asset hash for a TxIn
///
/// ### Arguments
///
/// * `asset`   - Asset to sign
pub fn construct_tx_in_signable_asset_hash(asset: &Asset) -> String {
    hex::encode(sha3_256::digest(
        get_asset_signable_string(asset).as_bytes(),
    ))
}

/// Constructs signable string for a StackEntry
///
/// ### Arguments
///
/// * `entry`   - StackEntry to obtain signable string for
pub fn get_stack_entry_signable_string(entry: &StackEntry) -> String {
    match entry {
        StackEntry::Op(op) => format!("Op:{op}"),
        StackEntry::Signature(signature) => {
            format!("Signature:{}", hex::encode(signature.as_ref()))
        }
        StackEntry::PubKey(pub_key) => format!("PubKey:{}", hex::encode(pub_key.as_ref())),
        StackEntry::PubKeyHash(pub_key_hash) => format!("PubKeyHash:{pub_key_hash}"),
        StackEntry::Num(num) => format!("Num:{num}"),
        StackEntry::Bytes(bytes) => format!("Bytes:{bytes}"),
    }
}

/// Constructs signable string for Script stack
///
///
/// ### Arguments
///
/// * `stack`   - StackEntry vector
pub fn get_script_signable_string(stack: &[StackEntry]) -> String {
    stack
        .iter()
        .map(get_stack_entry_signable_string)
        .collect::<Vec<String>>()
        .join("-")
}

/// Constructs signable string for TxIn
///
///
/// ### Arguments
///
/// * `tx_in`   - TxIn value
pub fn get_tx_in_address_signable_string(tx_in: &TxIn) -> String {
    let out_point_signable_string = match &tx_in.previous_out {
        Some(out_point) => get_out_point_signable_string(out_point),
        None => "null".to_owned(),
    };
    let script_signable_string = get_script_signable_string(&tx_in.script_signature.stack);
    format!("{out_point_signable_string}-{script_signable_string}")
}

/// Constructs address a TxIn collection
///
///
/// ### Arguments
///
/// * `tx_ins`   - TxIn collection
pub fn construct_tx_ins_address(tx_ins: &[TxIn]) -> String {
    let signable_tx_ins = tx_ins
        .iter()
        .map(get_tx_in_address_signable_string)
        .collect::<Vec<String>>()
        .join("-");
    hex::encode(sha3_256::digest(signable_tx_ins.as_bytes()))
}

/// Get all the hash to remove from UTXO set for the utxo_entries
///
/// ### Arguments
///
/// * `utxo_entries` - The entries to to provide an update for.
pub fn get_inputs_previous_out_point<'a>(
    utxo_entries: impl Iterator<Item = &'a Transaction>,
) -> impl Iterator<Item = &'a OutPoint> {
    utxo_entries
        .filter(|tx| !tx.is_create_tx())
        .flat_map(|val| val.inputs.iter())
        .map(|input| input.previous_out.as_ref().unwrap())
}

/// Get all the OutPoint and Transaction from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_tx_with_out_point<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)>,
) -> impl Iterator<Item = (OutPoint, &'a Transaction)> {
    txs.map(|(hash, tx)| (hash, tx, &tx.outputs))
        .flat_map(|(hash, tx, outs)| outs.iter().enumerate().map(move |(idx, _)| (hash, idx, tx)))
        .map(|(hash, idx, tx)| (OutPoint::new(hash.clone(), idx as i32), tx))
}

/// Get all the OutPoint and Transaction from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_tx_with_out_point_cloned<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)> + 'a,
) -> impl Iterator<Item = (OutPoint, Transaction)> + 'a {
    get_tx_with_out_point(txs).map(|(h, tx)| (h, tx.clone()))
}

/// Get all the OutPoint and TxOut from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_tx_out_with_out_point<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)>,
) -> impl Iterator<Item = (OutPoint, &'a TxOut)> {
    txs.map(|(hash, tx)| (hash, tx.outputs.iter()))
        .flat_map(|(hash, outs)| outs.enumerate().map(move |(idx, txo)| (hash, idx, txo)))
        .map(|(hash, idx, txo)| (OutPoint::new(hash.clone(), idx as i32), txo))
}

/// Get all the OutPoint and TxOut from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_tx_out_with_out_point_cloned<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)> + 'a,
) -> impl Iterator<Item = (OutPoint, TxOut)> + 'a {
    get_tx_out_with_out_point(txs).map(|(o, txo)| (o, txo.clone()))
}

/// Constructs the UTXO set for the current state of the blockchain
///
/// ### Arguments
///
/// * `current_utxo` - The current UTXO set to be updated.
pub fn update_utxo_set(current_utxo: &mut BTreeMap<OutPoint, Transaction>) {
    let value_set: Vec<OutPoint> = get_inputs_previous_out_point(current_utxo.values())
        .cloned()
        .collect();

    value_set.iter().for_each(move |t_hash| {
        current_utxo.remove(t_hash);
    });
}

/// Constructs a coinbase transaction
/// TODO: Adding block number to coinbase construction non-ideal. Consider moving to Compute
/// construction or mining later
///
/// ### Arguments
///
/// * `b_num`       - Block number for the current coinbase block
/// * `amount`      - Amount of tokens allowed in coinbase
/// * `address`     - Address to send the coinbase amount to
pub fn construct_coinbase_tx(b_num: u64, amount: TokenAmount, address: String) -> Transaction {
    let tx_in = TxIn::new_from_script(Script::new_for_coinbase(b_num));
    let tx_out = TxOut {
        value: Asset::Token(amount),
        script_public_key: Some(address),
        ..Default::default()
    };

    construct_tx_core(vec![tx_in], vec![tx_out])
}

/// Constructs a search-valid hash for a transaction to be added to the blockchain
///
/// ### Arguments
///
/// * `tx`  - Transaction to hash
pub fn construct_tx_hash(tx: &Transaction) -> String {
    let tx_bytes = Bytes::from(serialize(tx).unwrap());
    let tx_raw_h = sha3_256::digest(&tx_bytes).to_vec();
    let mut hash = hex::encode(tx_raw_h);

    hash.insert(0, TX_PREPEND as char);
    hash.truncate(32);

    hash
}

/// Construct a valid TxIn for a new create asset transaction
///
/// ### Arguments
///
/// * `block_num`   - Block number
/// * `asset`       - Asset to create
/// * `public_key`  - Public key to sign with
/// * `secret_key`  - Corresponding private key
fn construct_create_tx_in(
    block_num: u64,
    asset: &Asset,
    public_key: PublicKey,
    secret_key: &SecretKey,
) -> Vec<TxIn> {
    let asset_hash = construct_tx_in_signable_asset_hash(asset);
    let signature = sign::sign_detached(asset_hash.as_bytes(), secret_key);

    vec![TxIn {
        previous_out: None,
        script_signature: Script::new_create_asset(block_num, asset_hash, signature, public_key),
    }]
}

/// Constructs a transaction for the creation of a new smart data asset
///
/// ### Arguments
///
/// * `block_num`           - Block number
/// * `drs`                 - Digital rights signature for the new asset
/// * `public_key`          - Public key for the output address
/// * `secret_key`          - Corresponding secret key for signing data
/// * `amount`              - Amount of the asset to generate
pub fn construct_create_tx(
    block_num: u64,
    drs: Vec<u8>,
    public_key: PublicKey,
    secret_key: &SecretKey,
    amount: u64,
) -> Transaction {
    let asset = Asset::Data(DataAsset { data: drs, amount });
    let receiver_address = construct_address(&public_key);

    let tx_ins = construct_create_tx_in(block_num, &asset, public_key, secret_key);
    let tx_out = TxOut {
        value: asset,
        script_public_key: Some(receiver_address),
        ..Default::default()
    };

    construct_tx_core(tx_ins, vec![tx_out])
}

/// Constructs a receipt data asset for use in accepting payments
/// TODO: On compute, figure out a way to ease flow of receipts without issue for users
///
/// ### Arguments
///
/// * `block_num`           - Block number
/// * `public_key`          - Public key for the output address
/// * `secret_key`          - Corresponding secret key for signing data
/// * `amount`              - Amount of receipt assets to create
pub fn construct_receipt_create_tx(
    block_num: u64,
    public_key: PublicKey,
    secret_key: &SecretKey,
    amount: u64,
    drs_tx_hash_spec: DrsTxHashSpec,
    metadata: Option<String>,
) -> Transaction {
    let drs_tx_hash = drs_tx_hash_spec.get_drs_tx_hash();
    let asset = Asset::receipt(amount, drs_tx_hash, metadata);
    let receiver_address = construct_address(&public_key);

    let tx_ins = construct_create_tx_in(block_num, &asset, public_key, secret_key);
    let tx_out = TxOut {
        value: asset,
        script_public_key: Some(receiver_address),
        ..Default::default()
    };

    construct_tx_core(tx_ins, vec![tx_out])
}

/// Constructs a transaction to pay a receiver
///
/// TODO: Check whether the `amount` is valid in the TxIns
/// TODO: Call this a charity tx or something, as a payment is an exchange of goods
///
/// ### Arguments
///
/// * `tx_ins`              - Input/s to pay from
/// * `receiver_address`    - Address to send to
/// * `drs_block_hash`      - Hash of the block containing the original DRS. Only for data trades
/// * `asset`               - Asset to send
/// * `locktime`            - Block height below which the payment is restricted. "0" means no locktime
pub fn construct_payment_tx(
    tx_ins: Vec<TxIn>,
    receiver_address: String,
    drs_block_hash: Option<String>,
    asset: Asset,
    locktime: u64,
) -> Transaction {
    let tx_out = TxOut {
        value: asset,
        locktime,
        script_public_key: Some(receiver_address),
        drs_block_hash,
    };

    construct_tx_core(tx_ins, vec![tx_out])
}

/// Constructs a P2SH transaction to pay a receiver
///
/// ### Arguments
///
/// * `tx_ins`              - Input/s to pay from
/// * `script`              - Script to validate
/// * `drs_block_hash`      - Hash of the block containing the original DRS. Only for data trades
/// * `asset`               - Asset to send
/// * `locktime`            - Block height below which the payment is restricted. "0" means no locktime
pub fn construct_p2sh_tx(
    tx_ins: Vec<TxIn>,
    script: &Script,
    drs_block_hash: Option<String>,
    asset: Asset,
    locktime: u64,
) -> Transaction {
    let script_hash = construct_p2sh_address(script);

    let tx_out = TxOut {
        value: asset,
        locktime,
        script_public_key: Some(script_hash),
        drs_block_hash,
    };

    construct_tx_core(tx_ins, vec![tx_out])
}

/// Constructs a transaction to pay a receivers
/// If TxIn collection does not add up to the exact amount to pay,
/// payer will always need to provide a return payment in tx_outs,
/// otherwise the excess will be burnt and unusable.
///
/// TODO: Check whether the `amount` is valid in the TxIns
/// TODO: Call this a charity tx or something, as a payment is an exchange of goods
///
/// ### Arguments
///
/// * `tx_ins`     - Address/es to pay from
/// * `tx_outs`    - Address/es to send to
pub fn construct_tx_core(tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>) -> Transaction {
    Transaction {
        outputs: tx_outs,
        inputs: tx_ins,
        ..Default::default()
    }
}

/// Constructs a core receipt-based payment transaction
///
/// ### Arguments
///
/// * `from_address`    - Address receiving asset from
/// * `to_address`      - Address sending asset to
/// * `asset`           - Asset to send
/// * `tx_ins`          - TxIns for outgoing transaction
/// * `out`             - The TxOut for this send
/// * `druid`           - DRUID to match on
pub fn construct_rb_tx_core(
    tx_ins: Vec<TxIn>,
    tx_outs: Vec<TxOut>,
    druid: String,
    druid_expectation: Vec<DruidExpectation>,
) -> Transaction {
    let mut tx = construct_tx_core(tx_ins, tx_outs);
    tx.druid_info = Some(DdeValues {
        druid,
        participants: 2,
        expectations: druid_expectation,
    });

    tx
}

/// Constructs the "send" half of a receipt-based payment
/// transaction
///
/// ### Arguments
///
/// * `receiver_address`    - Own address to receive receipt to
/// * `amount`              - Amount of token to send
/// * `locktime`            - Block height to lock the current transaction to
pub fn construct_rb_payments_send_tx(
    tx_ins: Vec<TxIn>,
    mut tx_outs: Vec<TxOut>,
    receiver_address: String,
    amount: TokenAmount,
    locktime: u64,
    druid: String,
    expectation: Vec<DruidExpectation>,
) -> Transaction {
    let out = TxOut {
        value: Asset::Token(amount),
        locktime,
        script_public_key: Some(receiver_address),
        drs_block_hash: None,
    };
    tx_outs.push(out);
    construct_rb_tx_core(tx_ins, tx_outs, druid, expectation)
}

/// Constructs the "receive" half of a receipt-based payment
/// transaction
///
/// ### Arguments
///
/// * `tx_ins`              - Inputs to receipt data asset
/// * `sender_address`      - Address of sender
/// * `sender_send_addr`    - Input hash used by sender to send tokens
/// * `own_address`         - Own address to receive tokens to
/// * `amount`              - Number of tokens expected
/// * `locktime`            - Block height below which the payment receipt is restricted. "0" means no locktime
/// * `druid`               - The matching DRUID value
pub fn construct_rb_receive_payment_tx(
    tx_ins: Vec<TxIn>,
    mut tx_outs: Vec<TxOut>,
    sender_address: String,
    locktime: u64,
    druid: String,
    expectation: Vec<DruidExpectation>,
    drs_tx_hash: Option<String>,
) -> Transaction {
    let out = TxOut {
        value: Asset::receipt(1, drs_tx_hash, None),
        locktime,
        script_public_key: Some(sender_address),
        drs_block_hash: None, // this will need to change
    };
    tx_outs.push(out);
    construct_rb_tx_core(tx_ins, tx_outs, druid, expectation)
}

/// Constructs a set of TxIns for a payment
///
/// ### Arguments
///
/// * `tx_values`   - Series of values required for TxIn construction
pub fn construct_payment_tx_ins(tx_values: Vec<TxConstructor>) -> Vec<TxIn> {
    let mut tx_ins = Vec::new();

    for entry in tx_values {
        let signable_hash = construct_tx_in_signable_hash(&entry.previous_out);

        let previous_out = Some(entry.previous_out);
        let script_signature = Script::pay2pkh(
            signable_hash,
            entry.signatures[0],
            entry.pub_keys[0],
            entry.address_version,
        );

        tx_ins.push(TxIn {
            previous_out,
            script_signature,
        });
    }

    tx_ins
}

/// Constructs the TxIn for a P2SH redemption. The redeemer must supply a script that
/// matches the scriptPubKey of the output being spent.
///
/// ### Arguments
///
/// * `tx_values`   - Series of values required for TxIn construction
/// * `script`      - Script to be used in the scriptSig
pub fn construct_p2sh_redeem_tx_ins(tx_values: TxConstructor, script: Script) -> Vec<TxIn> {
    let mut tx_ins = Vec::new();
    let previous_out = Some(tx_values.previous_out);

    tx_ins.push(TxIn {
        previous_out,
        script_signature: script,
    });

    tx_ins
}

/// Constructs a dual double entry tx
///
/// ### Arguments
///
/// * `druid`                           - DRUID value to match with the other party
/// * `tx_ins`                          - Addresses to pay from
/// * `send_asset_drs_hash`             - Hash of the block containing the DRS for the sent asset. Only applicable to data trades
/// * `participants`                    - Participants in trade
/// * `(send_address, receive_address)` - Send and receive addresses as a tuple
/// * `(send_asset, receive_asset)`     - Send and receive assets as a tuple
pub fn construct_dde_tx(
    druid: String,
    tx_ins: Vec<TxIn>,
    tx_outs: Vec<TxOut>,
    participants: usize,
    expectations: Vec<DruidExpectation>,
) -> Transaction {
    let mut tx = construct_tx_core(tx_ins, tx_outs);
    tx.druid_info = Some(DdeValues {
        druid,
        participants,
        expectations,
    });

    tx
}

/*---- TESTS ----*/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sign_ed25519::{self as sign, Signature};
    use crate::primitives::asset::{AssetValues, ReceiptAsset};
    use crate::script::OpCodes;
    use crate::utils::script_utils::{tx_has_valid_p2sh_script, tx_outs_are_valid};

    #[test]
    // Creates a valid creation transaction
    fn test_construct_a_valid_create_tx() {
        let (pk, sk) = sign::gen_keypair();
        let receiver_address = construct_address(&pk);
        let amount = 1;
        let drs = vec![0, 8, 30, 20, 1];

        let tx = construct_create_tx(0, drs.clone(), pk, &sk, amount);

        assert!(tx.is_create_tx());
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.druid_info, None);
        assert_eq!(tx.outputs[0].drs_block_hash, None);
        assert_eq!(tx.outputs[0].script_public_key, Some(receiver_address));
        assert_eq!(
            tx.outputs[0].value,
            Asset::Data(DataAsset { data: drs, amount })
        );
    }

    #[test]
    // Creates a valid payment transaction
    fn test_construct_a_valid_payment_tx() {
        test_construct_a_valid_payment_tx_common(None);
    }

    #[test]
    // Creates a valid payment transaction
    fn test_construct_a_valid_payment_tx_v0() {
        test_construct_a_valid_payment_tx_common(Some(NETWORK_VERSION_V0));
    }

    #[test]
    // Creates a valid payment transaction
    fn test_construct_a_valid_payment_tx_temp() {
        test_construct_a_valid_payment_tx_common(Some(NETWORK_VERSION_TEMP));
    }

    fn test_construct_valid_inputs(address_version: Option<u64>) -> (Vec<TxIn>, String) {
        let (_pk, sk) = sign::gen_keypair();
        let (pk, _sk) = sign::gen_keypair();
        let t_hash = vec![0, 0, 0];
        let signature = sign::sign_detached(&t_hash, &sk);
        let drs_block_hash = hex::encode(vec![1, 2, 3, 4, 5, 6]);

        let tx_const = TxConstructor {
            previous_out: OutPoint::new(hex::encode(t_hash), 0),
            signatures: vec![signature],
            pub_keys: vec![pk],
            address_version,
        };

        let tx_ins = construct_payment_tx_ins(vec![tx_const]);

        (tx_ins, drs_block_hash)
    }

    #[test]
    fn test_construct_a_valid_p2sh_tx() {
        let token_amount = TokenAmount(400000);
        let (tx_ins, drs_block_hash) = test_construct_valid_inputs(Some(NETWORK_VERSION_V0));
        let mut script = Script::new_for_coinbase(10);
        script.stack.push(StackEntry::Op(OpCodes::OP_DROP));

        let p2sh_tx = construct_p2sh_tx(
            tx_ins,
            &script,
            Some(drs_block_hash.clone()),
            Asset::Token(token_amount),
            0,
        );

        let spending_tx_hash = construct_tx_hash(&p2sh_tx);

        let tx_const = TxConstructor {
            previous_out: OutPoint::new(spending_tx_hash, 0),
            signatures: vec![],
            pub_keys: vec![],
            address_version: Some(NETWORK_VERSION_V0),
        };

        let redeeming_tx_ins = construct_p2sh_redeem_tx_ins(tx_const, script.clone());
        let redeeming_tx = construct_payment_tx(
            redeeming_tx_ins,
            hex::encode(vec![0; 32]),
            Some(drs_block_hash),
            Asset::Token(token_amount),
            0,
        );
        let p2sh_script_pub_key = p2sh_tx.outputs[0].script_public_key.as_ref().unwrap();

        assert_eq!(Asset::Token(token_amount), p2sh_tx.outputs[0].value);
        assert_eq!(p2sh_script_pub_key.as_bytes()[0], P2SH_PREPEND);
        assert_eq!(p2sh_script_pub_key.len(), 32);
        assert!(tx_has_valid_p2sh_script(
            &redeeming_tx.inputs[0].script_signature,
            p2sh_tx.outputs[0].script_public_key.as_ref().unwrap()
        ));

        // TODO: Add assertion for full tx validity
    }

    fn test_construct_a_valid_payment_tx_common(address_version: Option<u64>) {
        let (tx_ins, drs_block_hash) = test_construct_valid_inputs(address_version);

        let token_amount = TokenAmount(400000);
        let payment_tx = construct_payment_tx(
            tx_ins,
            hex::encode(vec![0; 32]),
            Some(drs_block_hash),
            Asset::Token(token_amount),
            0,
        );

        assert_eq!(Asset::Token(token_amount), payment_tx.outputs[0].value);
        assert_eq!(
            payment_tx.outputs[0].script_public_key,
            Some(hex::encode(vec![0; 32]))
        );
    }

    #[test]
    /// Checks the validity of the metadata on-spend for receipts
    fn test_receipt_onspend_metadata() {
        let (_pk, sk) = sign::gen_keypair();
        let (pk, _sk) = sign::gen_keypair();
        let t_hash = vec![0, 0, 0];
        let signature = sign::sign_detached(&t_hash, &sk);
        let drs_block_hash = hex::encode(vec![1, 2, 3, 4, 5, 6]);

        let tx_const = TxConstructor {
            previous_out: OutPoint::new(hex::encode(t_hash), 0),
            signatures: vec![signature],
            pub_keys: vec![pk],
            address_version: Some(2),
        };

        let drs_tx_hash = "receipt_tx_hash".to_string();
        let receipt_asset_valid = ReceiptAsset::new(1000, Some(drs_tx_hash.clone()), None);

        let tx_ins = construct_payment_tx_ins(vec![tx_const]);
        let payment_tx_valid = construct_payment_tx(
            tx_ins,
            hex::encode(vec![0; 32]),
            Some(drs_block_hash),
            Asset::Receipt(receipt_asset_valid),
            0,
        );

        let mut btree = BTreeMap::new();
        btree.insert(drs_tx_hash, 1000);
        let tx_ins_spent = AssetValues::new(TokenAmount(0), btree);

        assert!(tx_outs_are_valid(&payment_tx_valid.outputs, tx_ins_spent));
    }

    #[test]
    // Creates a valid UTXO set
    fn test_construct_valid_utxo_set() {
        test_construct_valid_utxo_set_common(None);
    }

    #[test]
    // Creates a valid UTXO set
    fn test_construct_valid_utxo_set_v0() {
        test_construct_valid_utxo_set_common(Some(NETWORK_VERSION_V0));
    }

    #[test]
    // Creates a valid UTXO set
    fn test_construct_valid_utxo_set_temp() {
        test_construct_valid_utxo_set_common(Some(NETWORK_VERSION_TEMP));
    }

    fn test_construct_valid_utxo_set_common(address_version: Option<u64>) {
        let (pk, sk) = sign::gen_keypair();

        let t_hash_1 = hex::encode(vec![0, 0, 0]);
        let signed = sign::sign_detached(t_hash_1.as_bytes(), &sk);

        let tx_1 = TxConstructor {
            previous_out: OutPoint::new("".to_string(), 0),
            signatures: vec![signed],
            pub_keys: vec![pk],
            address_version,
        };

        let token_amount = TokenAmount(400000);
        let tx_ins_1 = construct_payment_tx_ins(vec![tx_1]);
        let payment_tx_1 = construct_payment_tx(
            tx_ins_1,
            hex::encode(vec![0; 32]),
            None,
            Asset::Token(token_amount),
            0,
        );
        let tx_1_hash = construct_tx_hash(&payment_tx_1);
        let tx_1_out_p = OutPoint::new(tx_1_hash.clone(), 0);

        // Second tx referencing first
        let tx_2 = TxConstructor {
            previous_out: OutPoint::new(tx_1_hash, 0),
            signatures: vec![signed],
            pub_keys: vec![pk],
            address_version,
        };
        let tx_ins_2 = construct_payment_tx_ins(vec![tx_2]);
        let tx_outs = vec![TxOut::new_token_amount(
            hex::encode(vec![0; 32]),
            token_amount,
        )];
        let payment_tx_2 = construct_tx_core(tx_ins_2, tx_outs);

        let tx_2_hash = construct_tx_hash(&payment_tx_2);
        let tx_2_out_p = OutPoint::new(tx_2_hash, 0);

        // BTreemap
        let mut btree = BTreeMap::new();
        btree.insert(tx_1_out_p, payment_tx_1);
        btree.insert(tx_2_out_p.clone(), payment_tx_2);

        update_utxo_set(&mut btree);

        // Check that only one entry remains
        assert_eq!(btree.len(), 1);
        assert_ne!(btree.get(&tx_2_out_p), None);
    }

    #[test]
    // Creates a valid DDE transaction
    fn test_construct_a_valid_dde_tx() {
        test_construct_a_valid_dde_tx_common(None);
    }

    #[test]
    // Creates a valid DDE transaction
    fn test_construct_a_valid_dde_tx_v0() {
        test_construct_a_valid_dde_tx_common(Some(NETWORK_VERSION_V0));
    }

    #[test]
    // Creates a valid DDE transaction
    fn test_construct_a_valid_dde_tx_temp() {
        test_construct_a_valid_dde_tx_common(Some(NETWORK_VERSION_TEMP));
    }

    fn test_construct_a_valid_dde_tx_common(address_version: Option<u64>) {
        let (_pk, sk) = sign::gen_keypair();
        let (pk, _sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let signature = sign::sign_detached(t_hash.as_bytes(), &sk);

        let to_asset = "2222".to_owned();
        let data = Asset::Data(DataAsset {
            data: vec![0, 12, 3, 5, 6],
            amount: 1,
        });

        let tx_const = TxConstructor {
            previous_out: OutPoint::new(hex::encode(&t_hash), 0),
            signatures: vec![signature],
            pub_keys: vec![pk],
            address_version,
        };

        let tx_ins = construct_payment_tx_ins(vec![tx_const]);
        let tx_outs = vec![TxOut {
            value: data.clone(),
            script_public_key: Some(to_asset.clone()),
            ..Default::default()
        }];

        let from_addr = hex::encode(serialize(&tx_ins).unwrap());

        // DDE params
        let druid = hex::encode(vec![1, 2, 3, 4, 5]);
        let participants = 2;
        let expects = vec![DruidExpectation {
            from: from_addr,
            to: to_asset,
            asset: data.clone(),
        }];

        // Actual DDE
        let dde = construct_dde_tx(druid.clone(), tx_ins, tx_outs, participants, expects);

        assert_eq!(dde.druid_info.clone().unwrap().druid, druid);
        assert_eq!(dde.outputs[0].clone().value, data);
        assert_eq!(dde.druid_info.unwrap().participants, participants);
    }

    #[test]
    // Creates a valid receipt based tx pair
    fn test_construct_a_valid_receipt_tx_pair() {
        // Arrange
        //
        let amount = TokenAmount(33);
        let payment = TokenAmount(11);
        let druid = "VALUE".to_owned();

        let tx_input = construct_payment_tx_ins(vec![]);
        let from_addr = construct_tx_ins_address(&tx_input);

        let alice_addr = "1111".to_owned();
        let bob_addr = "00000".to_owned();

        let sender_address_excess = "11112".to_owned();

        // Act
        //
        let send_tx = {
            let tx_ins = {
                // constructors with enough money for amount and excess, caller responsibility.
                construct_payment_tx_ins(vec![])
            };
            let excess_tx_out = TxOut::new_token_amount(sender_address_excess, amount - payment);

            let expectation = DruidExpectation {
                from: from_addr.clone(),
                to: alice_addr.clone(),
                asset: Asset::receipt(1, Some("drs_tx_hash".to_owned()), None),
            };

            let mut tx = construct_rb_payments_send_tx(
                tx_ins,
                Vec::new(),
                bob_addr.clone(),
                payment,
                0,
                druid.clone(),
                vec![expectation],
            );

            tx.outputs.push(excess_tx_out);

            tx
        };

        let recv_tx = {
            let tx_ins = {
                // constructors with enough money for amount and excess, caller responsibility.
                let tx_ins_constructor = vec![];
                construct_payment_tx_ins(tx_ins_constructor)
            };
            let expectation = DruidExpectation {
                from: from_addr,
                to: bob_addr,
                asset: Asset::Token(payment),
            };

            // create the sender that match the receiver.
            construct_rb_receive_payment_tx(
                tx_ins,
                Vec::new(),
                alice_addr,
                0,
                druid.clone(),
                vec![expectation],
                Some("drs_tx_hash".to_owned()),
            )
        };

        // Assert
        assert_eq!(
            send_tx
                .druid_info
                .as_ref()
                .map(|v| (&v.druid, v.participants)),
            Some((&druid, 2))
        );
        assert_eq!(
            recv_tx
                .druid_info
                .as_ref()
                .map(|v| (&v.druid, v.participants)),
            Some((&druid, 2))
        );
    }

    #[test]
    // Test valid address construction; should correlate with test on wallet
    fn test_construct_valid_addresses() {
        test_construct_valid_addresses_common(None);
    }

    #[test]
    // Test valid address construction; should correlate with test on wallet
    fn test_construct_valid_addresses_v0() {
        test_construct_valid_addresses_common(Some(NETWORK_VERSION_V0));
    }

    #[test]
    // Test valid address construction; should correlate with test on wallet
    fn test_construct_valid_addresses_temp() {
        test_construct_valid_addresses_common(Some(NETWORK_VERSION_TEMP));
    }

    fn test_construct_valid_addresses_common(address_version: Option<u64>) {
        //
        // Arrange
        //
        let pub_keys = vec![
            "5371832122a8e804fa3520ec6861c3fa554a7f6fb617e6f0768452090207e07c",
            "6e86cc1fc5efbe64c2690efbb966b9fe1957facc497dce311981c68dac88e08c",
            "8b835e00c57ebff6637ec32276f2c6c0df71129c8f0860131a78a4692a0b59dc",
        ]
        .iter()
        .map(|v| hex::decode(v).unwrap())
        .map(|v| PublicKey::from_slice(&v).unwrap())
        .collect::<Vec<PublicKey>>();

        //
        // Act
        //
        let actual_pub_addresses: Vec<String> = pub_keys
            .iter()
            .map(|pub_key| construct_address_for(pub_key, address_version))
            .collect();

        //
        // Assert
        //
        let expected_pub_addresses = match address_version {
            // Old Address structure
            Some(NETWORK_VERSION_V0) => vec![
                "13bd3351b78beb2d0dadf2058dcc926c",
                "abc7c0448465c4507faf2ee588728824",
                "6ae52e3870884ab66ec49d3bb359c0bf",
            ],
            // Temporary address structure present on wallet
            Some(NETWORK_VERSION_TEMP) => vec![
                "6c6b6e8e9df8c63d22d9eb687b9671dd1ce5d89f195bb2316e1b1444848cd2b3",
                "8ac2fdcb0688abb2727d63ed230665b275a1d3a28373baa92a9afa5afd610e9f",
                "0becdaaf6a855f04961208ee992651c11df0be91c08629dfc079d05d2915ec22",
            ],
            // Current address structure
            _ => vec![
                "5423e6bd848e0ce5cd794e55235c23138d8833633cd2d7de7f4a10935178457b",
                "77516e2d91606250e625546f86702510d2e893e4a27edfc932fdba03c955cc1b",
                "4cfd64a6692021fc417368a866d33d94e1c806747f61ac85e0b3935e7d5ed925",
            ],
        };
        assert_eq!(actual_pub_addresses, expected_pub_addresses);
    }

    #[test]
    // Test TxIn signable hash construction; should correlate with test on wallet
    fn test_construct_valid_tx_in_signable_hash() {
        //
        // Arrange
        //
        let out_points = vec![
            OutPoint::new("000000".to_owned(), 0),
            OutPoint::new("000001".to_owned(), 0),
            OutPoint::new("000002".to_owned(), 0),
        ];

        //
        // Act
        //
        let actual: Vec<String> = out_points
            .iter()
            .map(construct_tx_in_signable_hash)
            .collect();

        let expected: Vec<String> = vec![
            "927b3411743452e5e0d73e9e40a4fa3c842b3d00dabde7f9af7e44661ce02c88".to_owned(),
            "754dc248d1c847e8a10c6f8ded6ccad96381551ebb162583aea2a86b9bb78dfa".to_owned(),
            "5585c6f74d5c55f1ab457c31671822ba28c78c397cce1e11680b9f3852f96edb".to_owned(),
        ];

        //
        // Assert
        //
        assert_eq!(actual, expected);
    }

    #[test]
    // Test TxIn signable asset hash construction; should correlate with test on wallet
    fn test_construct_valid_tx_in_signable_asset_hash() {
        //
        // Arrange
        //
        let assets = vec![
            Asset::token_u64(1),
            Asset::receipt(1, None, None),
            Asset::Data(DataAsset {
                data: vec![1, 2, 3],
                amount: 1,
            }),
        ];

        //
        // Act
        //
        let actual: Vec<String> = assets
            .iter()
            .map(construct_tx_in_signable_asset_hash)
            .collect();

        let expected: Vec<String> = vec![
            "a5b2f5e8dcf824aee45b81294ff8049b680285b976cc6c8fa45eb070acfc5974".to_owned(),
            "ce86f26f7f44f92630031f83e8d2f26c58e88eae40583c8760082edc7407991f".to_owned(),
            "ab72cb41f1f18edfb9c5161029c9695de4d5eed1d323be18ddedfb66a2b32282".to_owned(),
        ];

        //
        // Assert
        //
        assert_eq!(actual, expected);
    }

    #[test]
    // Test valid TxIn address construction; should correlate with test on wallet
    fn test_construct_valid_tx_ins_address() {
        //
        // Arrange
        //
        let pub_keys = vec![
            "5e6d463ec66d7999769fa4de56f690dfb62e685b97032f5926b0cb6c93ba83c6",
            "58272ba93c1e79df280d4c417de47dbf6a7e330ba52793d7baa8e00ae5c34e59",
            "efa9dcba0f3282b3ed4a6aa1ccdb169d6685a30d7b2af7a2171a5682f3112359",
        ];

        let signatures = vec![
            "660e4698d817d409feb209699b15935048c8b3c4ac86a23f25b05aa32fb8b87e7cd029b83220d31a0b2717bd63b47a320a7728355d7fae43a665d6e27743e20d", 
            "fd107c9446cdcbd8fbb0d6b88c73067c9bd15de03fff677b0129acf1bd2d14a5ab8a63c7eb6fe8c5acc4b44b033744760847194a15b006368d178c85243d0605", 
            "e1a436bbfcb3e411be1ce6088cdb4c39d7e79f8fe427943e74307e43864fd0f6ef26123f1439b92c075edd031d17feb4dd265c6fcc2e5ed571df48a03c396100",
        ];

        let signable_data = vec![
            "927b3411743452e5e0d73e9e40a4fa3c842b3d00dabde7f9af7e44661ce02c88",
            "754dc248d1c847e8a10c6f8ded6ccad96381551ebb162583aea2a86b9bb78dfa",
            "5585c6f74d5c55f1ab457c31671822ba28c78c397cce1e11680b9f3852f96edb",
        ];

        let previous_out_points = vec![
            OutPoint::new("000000".to_owned(), 0),
            OutPoint::new("000001".to_owned(), 0),
            OutPoint::new("000002".to_owned(), 0),
        ];

        //
        // Act
        //
        let tx_ins: Vec<TxIn> = (0..3)
            .map(|n| {
                let sig_data = signable_data[n].to_owned();
                let sig =
                    Signature::from_slice(hex::decode(signatures[n]).unwrap().as_ref()).unwrap();
                let pk = PublicKey::from_slice(hex::decode(pub_keys[n]).unwrap().as_ref()).unwrap();

                let script = Script::pay2pkh(sig_data, sig, pk, None);
                let out_p = previous_out_points[n].clone();

                TxIn::new_from_input(out_p, script)
            })
            .collect();

        let expected =
            "a7b09a0ffc38e41318eb67c781279d4168f6e203810741284c2426b86ed28e3a".to_owned();
        let actual = construct_tx_ins_address(&tx_ins);

        //
        // Assert
        //
        assert_eq!(actual, expected);
    }
}
