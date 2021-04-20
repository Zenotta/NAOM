use crate::primitives::transaction::Transaction;
use crate::sha3::Digest;
use bincode::serialize;
use sha3::Sha3_256;
use std::collections::BTreeSet;
use std::iter::Extend;

/// Verifies that all DDE transaction expectations are met for DRUID-matching transactions
///
/// ### Arguments
///
/// * `druid`           - DRUID to match all transactions on
/// * `transactions`    - Transactions to verify
pub fn druid_expectations_are_met(druid: String, transactions: &[Transaction]) -> bool {
    let mut expects = BTreeSet::new();
    let mut expectation_collect = BTreeSet::new();

    for tx in transactions {
        if let Some(druid_info) = &tx.druid_info {
            let ins = hex::encode(Sha3_256::digest(&serialize(&tx.inputs).unwrap()).to_vec());

            // Ensure match with passed DRUID
            if druid_info.druid == druid {
                expects.extend(druid_info.expectations.iter());

                for out in &tx.outputs {
                    if let Some(pk) = &out.script_public_key {
                        expectation_collect.insert((ins.clone(), pk, &out.value));
                    }
                }
            }
        }
    }

    let expectation_met: BTreeSet<_> = expectation_collect
        .iter()
        .map(|(f, t, a)| (f, *t, *a))
        .collect();
    expects
        .iter()
        .all(|e| expectation_met.contains(&(&e.from, &e.to, &e.asset)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::asset::{Asset, DataAsset, TokenAmount};
    use crate::primitives::druid::{DdeValues, DruidExpectation};
    use crate::primitives::transaction::*;
    use crate::utils::transaction_utils::*;

    /// Util function to create valid DDE asset tx's
    fn create_dde_txs() -> Vec<Transaction> {
        let druid = "VALUE".to_owned();
        let tx_input = construct_payment_tx_ins(vec![]);
        let from_addr = hex::encode(Sha3_256::digest(&serialize(&tx_input).unwrap()).to_vec());

        // Alice
        let amount = TokenAmount(10);
        let alice_addr = "3333".to_owned();
        let alice_asset = Asset::Token(amount);

        // Bob
        let bob_asset = Asset::Data(DataAsset {
            data: "453094573049875".as_bytes().to_vec(),
            amount: 1,
        });
        let bob_addr = "22222".to_owned();

        // TxOuts
        let token_tx_out = TxOut {
            value: alice_asset.clone(),
            script_public_key: Some(bob_addr.clone()),
            ..Default::default()
        };

        let data_tx_out = TxOut {
            value: bob_asset.clone(),
            script_public_key: Some(alice_addr.clone()),
            ..Default::default()
        };

        // Expectations (from addresses the same due to empty TxIn)
        let expects = vec![
            DruidExpectation {
                from: from_addr.clone(),
                to: bob_addr,
                asset: alice_asset,
            },
            DruidExpectation {
                from: from_addr,
                to: alice_addr,
                asset: bob_asset,
            },
        ];

        // Txs
        let alice_tx = construct_dde_tx(
            druid.clone(),
            tx_input.clone(),
            vec![token_tx_out],
            2,
            expects.clone(),
        );

        let bob_tx = construct_dde_tx(druid, tx_input, vec![data_tx_out], 2, expects);

        vec![alice_tx, bob_tx]
    }

    /// Util function to create valid receipt-based payment tx's
    fn create_rb_payment_txs() -> (Transaction, Transaction) {
        // Arrange
        //
        let amount = TokenAmount(33);
        let payment = TokenAmount(11);
        let druid = "VALUE".to_owned();

        let tx_input = construct_payment_tx_ins(vec![]);
        let from_addr = hex::encode(Sha3_256::digest(&serialize(&tx_input).unwrap()).to_vec());

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
            let excess_tx_out = TxOut::new_amount(sender_address_excess, amount - payment);

            let expectation = DruidExpectation {
                from: from_addr.clone(),
                to: alice_addr.clone(),
                asset: Asset::Receipt(1),
            };

            let mut tx = construct_rb_payments_send_tx(
                tx_ins,
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
            construct_rb_receive_payment_tx(tx_ins, alice_addr, 0, druid, vec![expectation])
        };

        (send_tx, recv_tx)
    }

    #[test]
    /// Checks that matching DDE transactions are verified as such by DDE verifier
    fn should_pass_matching_dde_tx_valid() {
        let txs = create_dde_txs();
        assert!(druid_expectations_are_met("VALUE".to_owned(), &txs));
    }

    #[test]
    /// Checks that DDE transactions with non-matching expects fail
    fn should_fail_dde_tx_value_expect_mismatch() {
        let mut txs = create_dde_txs();
        let mut change_tx = txs.pop().unwrap();
        let orig_tx = txs[0].clone();

        let druid_info = change_tx.druid_info.clone();
        let mut expects = druid_info.unwrap().expectations;
        expects[0].to = "60764505679457".to_string();

        // New druid info
        let nm_druid_info = DdeValues {
            druid: "VALUE".to_owned(),
            participants: 2,
            expectations: expects,
        };
        change_tx.druid_info = Some(nm_druid_info);

        assert_eq!(
            druid_expectations_are_met("VALUE".to_owned(), &vec![orig_tx, change_tx]),
            false
        );
    }

    #[test]
    /// Checks that matching receipt-based payments are verified as such by the DDE verifier
    fn should_pass_matching_rb_payment_valid() {
        let (send_tx, recv_tx) = create_rb_payment_txs();
        assert!(druid_expectations_are_met(
            "VALUE".to_owned(),
            &vec![send_tx, recv_tx]
        ));
    }

    #[test]
    /// Checks that receipt-based payments with non-matching DRUIDs fail
    fn should_fail_rb_payment_druid_mismatch() {
        let (send_tx, mut recv_tx) = create_rb_payment_txs();

        let mut druid_info = recv_tx.druid_info.unwrap();
        druid_info.druid = "Not_VAlue".to_owned();
        recv_tx.druid_info = Some(druid_info);

        // Non-matching druid
        assert_eq!(
            druid_expectations_are_met("VALUE".to_owned(), &vec![send_tx, recv_tx]),
            false
        );
    }

    #[test]
    /// Checks that receipt-based payments with non-matching addresses fail
    fn should_fail_rb_payment_addr_mismatch() {
        let (send_tx, mut recv_tx) = create_rb_payment_txs();
        recv_tx.outputs[0].script_public_key = Some("11145".to_string());

        // Non-matching address expectation
        assert_eq!(
            druid_expectations_are_met("VALUE".to_owned(), &vec![send_tx, recv_tx]),
            false
        );
    }

    #[test]
    /// Checks that receipt-based payments with non-matching value expectations fail
    fn should_fail_rb_payment_value_expect_mismatch() {
        let (mut send_tx, recv_tx) = create_rb_payment_txs();
        send_tx.outputs[0].value = Asset::Token(TokenAmount(10));

        // Non-matching address expectation
        assert_eq!(
            druid_expectations_are_met("VALUE".to_owned(), &vec![send_tx, recv_tx]),
            false
        );
    }
}
