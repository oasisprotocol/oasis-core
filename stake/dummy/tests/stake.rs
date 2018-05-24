extern crate ekiden_common;
extern crate ekiden_stake_base;
extern crate ekiden_stake_dummy;

use std::collections::HashSet;
use std::sync::Arc;

use ekiden_common::bytes::B256;
use ekiden_common::futures::Future;
use ekiden_stake_base::*;
use ekiden_stake_dummy::*;

#[test]
fn test_dummy_stake_backend() {
    let backend = Arc::new(DummyStakeEscrowBackend::new());
    let mut id_generator = LittleEndianCounter32::new();

    let alice = id_generator.to_b256();
    id_generator.incr_mut();

    backend.deposit_stake(alice, 100).wait().unwrap();

    let stake_status = backend.get_stake_status(alice).wait().unwrap();
    assert_eq!(stake_status.total_stake, 100);
    assert_eq!(stake_status.escrowed, 0);

    let bob = id_generator.to_b256();
    id_generator.incr_mut();

    let bob_escrow_id = backend.allocate_escrow(alice, bob, 9).wait().unwrap();

    println!("got escrow id {} for bob", bob_escrow_id);

    let stake_status = backend.get_stake_status(alice).wait().unwrap();
    assert_eq!(stake_status.total_stake, 100);
    assert_eq!(stake_status.escrowed, 9);

    let carol = id_generator.to_b256();
    id_generator.incr_mut();
    let carol_escrow_id = backend.allocate_escrow(alice, carol, 13).wait().unwrap();

    println!("got escrow id {} for carol", carol_escrow_id);

    let mut expected = HashSet::new();
    expected.insert((bob_escrow_id, bob, 9));
    expected.insert((carol_escrow_id, carol, 13));
    for triple in &expected {
        println!("expected: ({}, {}, {})", triple.0, triple.1, triple.2);
    }
    let ved = backend.list_active_escrows(alice).wait().unwrap();
    let mut actual = HashSet::new();
    for ed in &ved {
        let escrow_id = B256::from_slice(ed.get_escrow_id());
        let target = B256::from_slice(ed.get_entity());
        println!("escrow_id: {}", escrow_id);
        println!("target: {}", target);
        println!("amount: {}", ed.get_amount());

        actual.insert((escrow_id, target, ed.get_amount()));
    }

    let d: HashSet<_> = expected.symmetric_difference(&actual).collect();
    for triple in &d {
        println!("sd: ({}, {}, {})", triple.0, triple.1, triple.2);
    }
    assert!(d.is_empty());

    // Should we now check that ved is actually sorted?  This is only
    // a part of the interface to minimize information leak, so maybe
    // later: we should make the EscrowAccount type public for
    // testing, convert the ved via a map to that, ....

    let withdrawn_amount = backend.withdraw_stake(alice, 10).wait().unwrap();
    assert_eq!(withdrawn_amount, 10);

    let stake_status = backend.get_stake_status(alice).wait().unwrap();
    assert_eq!(stake_status.total_stake, 100 - 10);
    assert_eq!(stake_status.escrowed, 9 + 13);

    let ed = backend.fetch_escrow_by_id(bob_escrow_id).wait().unwrap();
    assert_eq!(B256::from_slice(ed.get_escrow_id()), bob_escrow_id);
    assert_eq!(B256::from_slice(ed.get_entity()), bob);
    assert_eq!(ed.get_amount(), 9);

    let t = backend
        .take_and_release_escrow(bob, bob_escrow_id, 10)
        .wait();
    match t {
        Err(e) => {
            println!("Got error {}", e.message);
            assert_eq!(e.message, REQUEST_EXCEEDS_ESCROWED);
        }
        Ok(v) => {
            println!("Got amount {} when request should have failed", v);
            assert!(false);
        }
    }
    println!("taking 5");
    assert_eq!(
        backend
            .take_and_release_escrow(bob, bob_escrow_id, 5)
            .wait()
            .unwrap(),
        5
    );
    match backend.fetch_escrow_by_id(bob_escrow_id).wait() {
        Err(e) => {
            println!("Got error {}", e.message);
            assert_eq!(e.message, NO_ESCROW_ACCOUNT);
        }
        Ok(ed) => {
            println!(
                "Found escrow account {} when request should have failed, entity {}, amount {}",
                B256::from_slice(ed.get_escrow_id()),
                B256::from_slice(ed.get_entity()),
                ed.get_amount()
            );
            assert!(false);
        }
    }

    let stake_status = backend.get_stake_status(alice).wait().unwrap();
    assert_eq!(stake_status.total_stake, 100 - 10 - 5);
    assert_eq!(stake_status.escrowed, 13);

    match backend.get_stake_status(bob).wait() {
        Err(e) => {
            println!("Got error {}", e.message);
            assert_eq!(e.message, NO_STAKE_ACCOUNT);
        }
        Ok(ss) => {
            println!("Got stake status when call should have failed");
            println!(" total_stake: {}", ss.total_stake);
            println!(" escrowed: {}", ss.escrowed);
        }
    }
}
