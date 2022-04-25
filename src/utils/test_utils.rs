use crate::crypto::sign_ed25519::{self as sign};
use crate::primitives::{
    asset::TokenAmount,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};
use crate::script::lang::Script;
use crate::utils::transaction_utils::{construct_address, construct_tx_in_signable_hash};
use std::collections::BTreeMap;

/// Generate a transaction with valid Script values
/// and accompanying UTXO set for testing a set of
/// input values and output values.
///
/// ### Purpose:
///
/// The purpose of this utility function is to generate a transaction that
/// exhibits a valid Script, but may or may not contain invalid `drs_tx_hash`
/// values for a configuration of `TxIn` values and their corresponding `TxOut` values
///
/// `Receipt` assets may **NOT** be on-spent if the `TxIn` value has a different
/// `drs_tx_hash` value than the ongoing `TxOut` value
///
/// ### Note:
///
/// When a `None` value is presented alongside an input amount, the asset is assumed
/// to be of type `Token`.
pub fn generate_tx_with_ins_and_outs_assets(
    input_assets: &[(u64, Option<&str>)], /* Input amount, drs_tx_hash */
    output_assets: &[(u64, Option<&str>)], /* Input amount, drs_tx_hash */
) -> (BTreeMap<OutPoint, TxOut>, Transaction) {
    let (pk, sk) = sign::gen_keypair();
    let spk = construct_address(&pk);
    let mut tx = Transaction::new();
    let mut utxo_set: BTreeMap<OutPoint, TxOut> = BTreeMap::new();

    // Generate inputs
    for (input_amount, drs_tx_hash) in input_assets {
        let tx_previous_out = OutPoint::new("tx_hash".to_owned(), tx.inputs.len() as i32);
        let tx_in_previous_out = match drs_tx_hash {
            Some(drs) => {
                TxOut::new_receipt_amount(spk.clone(), *input_amount, Some(drs.to_string()))
            }
            None => TxOut::new_token_amount(spk.clone(), TokenAmount(*input_amount)),
        };
        let signable_hash = construct_tx_in_signable_hash(&tx_previous_out);
        let signature = sign::sign_detached(signable_hash.as_bytes(), &sk);
        let tx_in = TxIn::new_from_input(
            tx_previous_out.clone(),
            Script::pay2pkh(signable_hash, signature, pk, None),
        );
        utxo_set.insert(tx_previous_out, tx_in_previous_out);
        tx.inputs.push(tx_in);
    }

    // Generate outputs
    for (output_amount, drs_tx_hash) in output_assets {
        let tx_out = match drs_tx_hash {
            Some(drs) => {
                TxOut::new_receipt_amount(spk.clone(), *output_amount, Some(drs.to_string()))
            }
            None => TxOut::new_token_amount(spk.clone(), TokenAmount(*output_amount)),
        };
        tx.outputs.push(tx_out);
    }

    (utxo_set, tx)
}
