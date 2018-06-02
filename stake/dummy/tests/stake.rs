extern crate ekiden_common;
extern crate ekiden_stake_base;
extern crate ekiden_stake_dummy;

use std::collections::HashSet;
use std::sync::Arc;

use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
use ekiden_common::futures::Future;
use ekiden_common::uint::U256;
use ekiden_stake_base::*;
use ekiden_stake_dummy::*;

#[derive(Copy, Clone)]
struct IdGenerator {
    id: U256,
}

fn get_and_show_stake(backend: &Arc<DummyStakeEscrowBackend>, id: B256, name: &str) -> StakeStatus {
    let ss = backend.get_stake_status(id).wait().unwrap();
    println!("{}'s stake status:", name);
    println!(" total_stake: {}", ss.total_stake);
    println!(" escrowed: {}", ss.escrowed);
    ss
}

impl IdGenerator {
    fn new() -> Self {
        Self { id: U256::from(0) }
    }

    fn get(&self) -> B256 {
        B256::from_slice(&self.id.to_vec())
    }

    fn incr_mut(&mut self) -> Result<(), Error> {
        let mut next = self.id;
        next = next + U256::from(1);
        if next == U256::from(0) {
            return Err(Error::new("OVERFLOW"));
        }
        self.id = next;
        Ok(())
    }

    fn gen_id(&mut self) -> B256 {
        let rv = self.get();
        self.incr_mut().unwrap();
        rv
    }
}

#[test]
fn test_dummy_stake_backend() {
    let backend = Arc::new(DummyStakeEscrowBackend::new());
    let mut id_generator = IdGenerator::new();

    let alice = id_generator.gen_id();

    backend.deposit_stake(alice, 100).wait().unwrap();

    let stake_status = get_and_show_stake(&backend, alice, "Alice");
    assert_eq!(stake_status.total_stake, 100);
    assert_eq!(stake_status.escrowed, 0);

    let bob = id_generator.gen_id();

    let bob_escrow_id = backend.allocate_escrow(alice, bob, 9).wait().unwrap();

    println!("got escrow id {} for bob", bob_escrow_id);

    let stake_status = get_and_show_stake(&backend, alice, "Alice");
    assert_eq!(stake_status.total_stake, 100);
    assert_eq!(stake_status.escrowed, 9);

    let carol = id_generator.gen_id();
    let carol_escrow_id = backend.allocate_escrow(alice, carol, 13).wait().unwrap();

    println!("got escrow id {} for carol", carol_escrow_id);

    let mut expected = HashSet::new();
    expected.insert((bob_escrow_id, bob, 9));
    expected.insert((carol_escrow_id, carol, 13));
    for triple in &expected {
        println!("expected: ({}, {}, {})", triple.0, triple.1, triple.2);
    }
    let veas = backend.list_active_escrows(alice).wait().unwrap();
    let mut actual = HashSet::new();
    for eas in &veas {
        println!("escrow_id: {}", eas.id);
        println!("target: {}", eas.target);
        println!("amount: {}", eas.amount);

        actual.insert((eas.id, eas.target, eas.amount));
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

    let eas = backend.fetch_escrow_by_id(bob_escrow_id).wait().unwrap();
    assert_eq!(eas.id, bob_escrow_id);
    assert_eq!(eas.target, bob);
    assert_eq!(eas.amount, 9);

    println!("taking 10 -- too much, should fail");
    match backend
        .take_and_release_escrow(bob, bob_escrow_id, 10)
        .wait()
    {
        Err(e) => {
            println!("Got error {}", e.message);
            assert_eq!(
                e.message,
                ErrorCodes::RequestExceedsEscrowedFunds.to_string()
            );
        }
        Ok(v) => {
            println!("Got amount {} when request should have failed", v);
            assert!(false);
        }
    }

    println!("carol attempts to take 4");
    match backend
        .take_and_release_escrow(carol, bob_escrow_id, 4)
        .wait()
    {
        Err(e) => {
            println!("Got error {}", e.message);
            assert_eq!(e.message, ErrorCodes::CallerNotEscrowTarget.to_string());
        }
        Ok(amount) => {
            println!("Got {}!!!", amount);
            assert!(false);
        }
    };

    println!("bob taking 5");
    assert_eq!(
        backend
            .take_and_release_escrow(bob, bob_escrow_id, 5)
            .wait()
            .unwrap(),
        5
    );

    println!("escrow id should be invalid");
    match backend.fetch_escrow_by_id(bob_escrow_id).wait() {
        Err(e) => {
            println!("Got error {}", e.message);
            assert_eq!(e.message, ErrorCodes::NoEscrowAccount.to_string());
        }
        Ok(eas) => {
            println!(
                "Found escrow account {} when request should have failed, target {}, amount {}",
                eas.id, eas.target, eas.amount
            );
            assert!(false);
        }
    }

    let stake_status = backend.get_stake_status(alice).wait().unwrap();
    assert_eq!(stake_status.total_stake, 100 - 10 - 5);
    assert_eq!(stake_status.escrowed, 13);

    println!("bob's account should have been credited");
    let ss = get_and_show_stake(&backend, bob, "Bob");
    assert_eq!(ss.total_stake, 5);
    assert_eq!(ss.escrowed, 0);

    println!("transfer from bob to carol -- too much");
    match backend.transfer_stake(bob, carol, 100).wait() {
        Err(e) => {
            println!("Got error {}", e.message);
            assert_eq!(e.message, ErrorCodes::InsufficientFunds.to_string());
        }
        Ok(_) => {
            println!("Transfer should not have succeeded.");
            assert!(false);
        }
    }

    println!("transfer from bob to carol -- some (2)");
    backend.transfer_stake(bob, carol, 2).wait().unwrap();
    // verify amounts
    let ss = get_and_show_stake(&backend, bob, "Bob");
    assert_eq!(ss.total_stake, 3);
    assert_eq!(ss.escrowed, 0);
    let ss = get_and_show_stake(&backend, carol, "Carol");
    assert_eq!(ss.total_stake, 2);
    assert_eq!(ss.escrowed, 0);

    // Transfer all
    println!("transfer from bob to carol -- all");
    backend.transfer_stake(bob, carol, 3).wait().unwrap();
    // verify amounts
    let ss = get_and_show_stake(&backend, bob, "Bob");
    assert_eq!(ss.total_stake, 0);
    assert_eq!(ss.escrowed, 0);

    let ss = get_and_show_stake(&backend, carol, "Carol");
    assert_eq!(ss.total_stake, 5);
    assert_eq!(ss.escrowed, 0);

    println!("transfer from alice to bob -- should be insufficient");
    match backend
        .transfer_stake(alice, bob, 100 - 10 - 5 - 13 + 1)
        .wait()
    {
        Err(e) => {
            println!("Got error {}", e.message);
            assert_eq!(e.message, ErrorCodes::InsufficientFunds.to_string());
        }
        Ok(_) => {
            println!("Transfer succeeded.");
            assert!(false);
        }
    }

    println!("transfer from alice to dexter -- should create dexter account");
    let dexter = id_generator.gen_id();
    backend.transfer_stake(alice, dexter, 17).wait().unwrap();
    // verify amounts
    let ss = get_and_show_stake(&backend, alice, "Alice");
    assert_eq!(ss.total_stake, 100 - 10 - 5 - 17);
    assert_eq!(ss.escrowed, 13);

    let ss = get_and_show_stake(&backend, dexter, "Dexter");
    assert_eq!(ss.total_stake, 17);
    assert_eq!(ss.escrowed, 0);
}
