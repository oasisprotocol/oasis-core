extern crate ekiden_common;
extern crate ekiden_stake_base;
extern crate ekiden_stake_dummy;

#[macro_use]
extern crate log;

use std::collections::HashSet;
use std::sync::Arc;

use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
use ekiden_common::futures::Future;
use ekiden_common::testing::try_init_logging;
use ekiden_common::uint::U256;
use ekiden_stake_base::*;
use ekiden_stake_dummy::*;

#[derive(Copy, Clone)]
struct IdGenerator {
    id: U256,
}

fn get_and_show_stake(backend: &Arc<DummyStakeEscrowBackend>, id: B256, name: &str) -> StakeStatus {
    let ss = backend.get_stake_status(id).wait().unwrap();
    debug!("{}'s stake status:", name);
    debug!(" total_stake: {}", ss.total_stake);
    debug!(" escrowed: {}", ss.escrowed);
    ss
}

impl IdGenerator {
    fn new() -> Self {
        Self { id: U256::from(1) }
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
    try_init_logging();

    let mut id_generator = IdGenerator::new();
    let oasis = id_generator.gen_id();

    let backend = Arc::new(DummyStakeEscrowBackend::new(
        oasis, "EkidenStake", "E$", AmountType::from(1),
    ));

    let alice = id_generator.gen_id();

    backend.deposit_stake(alice, AmountType::from(100)).wait().unwrap();

    let stake_status = get_and_show_stake(&backend, alice, "Alice");
    assert_eq!(stake_status.total_stake, AmountType::from(100));
    assert_eq!(stake_status.escrowed, AmountType::from(0));

    let bob = id_generator.gen_id();

    let bob_escrow_id = backend.allocate_escrow(alice, bob, AmountType::from(9)).wait().unwrap();

    debug!("got escrow id {} for bob", bob_escrow_id);

    let stake_status = get_and_show_stake(&backend, alice, "Alice");
    assert_eq!(stake_status.total_stake, AmountType::from(100));
    assert_eq!(stake_status.escrowed, AmountType::from(9));

    let carol = id_generator.gen_id();
    let carol_escrow_id = backend.allocate_escrow(alice, carol, AmountType::from(13)).wait().unwrap();

    debug!("got escrow id {} for carol", carol_escrow_id);

    let mut expected = HashSet::new();
    expected.insert((bob_escrow_id, bob, AmountType::from(9)));
    expected.insert((carol_escrow_id, carol, AmountType::from(13)));
    for triple in &expected {
        debug!("expected: ({}, {}, {})", triple.0, triple.1, triple.2);
    }
    let veas = backend.list_active_escrows(alice).wait().unwrap();
    let mut actual = HashSet::new();
    for eas in &veas {
        debug!("escrow_id: {}", eas.id);
        debug!("target: {}", eas.target);
        debug!("amount: {}", eas.amount);

        actual.insert((eas.id, eas.target, eas.amount));
    }
    let d: HashSet<_> = expected.symmetric_difference(&actual).collect();
    for triple in &d {
        debug!("sd: ({}, {}, {})", triple.0, triple.1, triple.2);
    }
    assert!(d.is_empty());

    // Should we now check that ved is actually sorted?  This is only
    // a part of the interface to minimize information leak, so maybe
    // later: we should make the EscrowAccount type public for
    // testing, convert the ved via a map to that, ....

    let withdrawn_amount = backend.withdraw_stake(alice, AmountType::from(10)).wait().unwrap();
    assert_eq!(withdrawn_amount, AmountType::from(10));

    let stake_status = backend.get_stake_status(alice).wait().unwrap();
    assert_eq!(stake_status.total_stake, AmountType::from(100 - 10));
    assert_eq!(stake_status.escrowed, AmountType::from(9 + 13));

    let eas = backend.fetch_escrow_by_id(bob_escrow_id).wait().unwrap();
    assert_eq!(eas.id, bob_escrow_id);
    assert_eq!(eas.target, bob);
    assert_eq!(eas.amount, AmountType::from(9));

    debug!("taking 10 -- too much, should fail");
    match backend
        .take_and_release_escrow(bob, bob_escrow_id, AmountType::from(10))
        .wait()
    {
        Err(e) => {
            debug!("Got error {}", e.message);
            assert_eq!(
                e.message,
                ErrorCodes::RequestExceedsEscrowedFunds.to_string()
            );
        }
        Ok(v) => {
            error!(
                "Got amount {} when take request should have failed (RequestExceedsEscrowedFunds)",
                v
            );
            assert!(false);
        }
    }

    debug!("carol attempts to take 4");
    match backend
        .take_and_release_escrow(carol, bob_escrow_id, AmountType::from(4))
        .wait()
    {
        Err(e) => {
            debug!("Got error {}", e.message);
            assert_eq!(e.message, ErrorCodes::CallerNotEscrowTarget.to_string());
        }
        Ok(amount) => {
            error!("Got {} instead of failing when Carol attempting to take too much (CallerNotEscrowTarget)", amount);
            assert!(false);
        }
    };

    debug!("bob taking 5");
    assert_eq!(
        backend
            .take_and_release_escrow(bob, bob_escrow_id, AmountType::from(5))
            .wait()
            .unwrap(),
        5
    );

    debug!("escrow id should be invalid");
    match backend.fetch_escrow_by_id(bob_escrow_id).wait() {
        Err(e) => {
            debug!("Got error {}", e.message);
            assert_eq!(e.message, ErrorCodes::NoEscrowAccount.to_string());
        }
        Ok(eas) => {
            error!(
                "Found escrow account {} when request should have failed, target {}, amount {} (NoEscrowAccount)",
                eas.id, eas.target, eas.amount
            );
            assert!(false);
        }
    }

    let stake_status = backend.get_stake_status(alice).wait().unwrap();
    assert_eq!(stake_status.total_stake, AmountType::from(100 - 10 - 5));
    assert_eq!(stake_status.escrowed, AmountType::from(13));

    debug!("bob's account should have been credited");
    let ss = get_and_show_stake(&backend, bob, "Bob");
    assert_eq!(ss.total_stake, AmountType::from(5));
    assert_eq!(ss.escrowed, AmountType::from(0));

    debug!("transfer from bob to carol -- too much");
    match backend.transfer(bob, carol, AmountType::from(100)).wait() {
        Err(e) => {
            debug!("Got error {}", e.message);
            assert_eq!(e.message, ErrorCodes::InsufficientFunds.to_string());
        }
        Ok(_) => {
            error!("Transfer from bob to carol (too much) should not have succeeded (InsufficientFunds).");
            assert!(false);
        }
    }

    debug!("transfer from bob to carol -- some (2)");
    backend.transfer(bob, carol, AmountType::from(2)).wait().unwrap();
    // verify amounts
    let ss = get_and_show_stake(&backend, bob, "Bob");
    assert_eq!(ss.total_stake, AmountType::from(3));
    assert_eq!(ss.escrowed, AmountType::from(0));
    let ss = get_and_show_stake(&backend, carol, "Carol");
    assert_eq!(ss.total_stake, AmountType::from(2));
    assert_eq!(ss.escrowed, AmountType::from(0));

    // Transfer all
    debug!("transfer from bob to carol -- all");
    backend.transfer(bob, carol, AmountType::from(3)).wait().unwrap();
    // verify amounts
    let ss = get_and_show_stake(&backend, bob, "Bob");
    assert_eq!(ss.total_stake, AmountType::from(0));
    assert_eq!(ss.escrowed, AmountType::from(0));

    let ss = get_and_show_stake(&backend, carol, "Carol");
    assert_eq!(ss.total_stake, AmountType::from(5));
    assert_eq!(ss.escrowed, AmountType::from(0));

    debug!("transfer from alice to bob -- should be insufficient");
    match backend
        .transfer(alice, bob, AmountType::from(100 - 10 - 5 - 13 + 1))
        .wait()
    {
        Err(e) => {
            debug!("Got error {}", e.message);
            assert_eq!(e.message, ErrorCodes::InsufficientFunds.to_string());
        }
        Ok(_) => {
            error!("Transfer from alice to bob should not have succeeded (InsufficientFunds).");
            assert!(false);
        }
    }

    debug!("transfer from alice to dexter -- should create dexter account");
    let dexter = id_generator.gen_id();
    backend.transfer(alice, dexter, AmountType::from(17)).wait().unwrap();
    // verify amounts
    let ss = get_and_show_stake(&backend, alice, "Alice");
    assert_eq!(ss.total_stake, AmountType::from(100 - 10 - 5 - 17));
    assert_eq!(ss.escrowed, AmountType::from(13));

    let ss = get_and_show_stake(&backend, dexter, "Dexter");
    assert_eq!(ss.total_stake, AmountType::from(17));
    assert_eq!(ss.escrowed, AmountType::from(0));

    // ----------------------------------------------------
    // self transfer
    // ----------------------------------------------------
    debug!("transfer from dexter to dexter");
    backend.transfer(dexter, dexter, 17).wait().unwrap();
    let ss = get_and_show_stake(&backend, dexter, "Dexter");
    assert_eq!(ss.total_stake, AmountType::from(17));
    assert_eq!(ss.escrowed, AmountType::from(0));
    // ----------------------------------------------------
    debug!("transfer too much from dexter to dexter");
    match backend.transfer(dexter, dexter, AmountType::from(19)).wait() {
        Err(e) => {
            debug!("Got error {}", e.message);
            assert_eq!(e.message, ErrorCodes::InsufficientFunds.to_string());
        }
        Ok(_) => {
            error!("Transfer from dexter to dexter succeeded but shouldn't (InsufficientFunds).");
            assert!(false);
        }
    }
    let ss = get_and_show_stake(&backend, dexter, "Dexter");
    assert_eq!(ss.total_stake, AmountType::from(17));
    assert_eq!(ss.escrowed, AmountType::from(0));

    // ----------------------------------------------------
    // Self escrow & release
    // ----------------------------------------------------
    debug!("create escrow from alice to alice");
    let self_escrow_id = backend.allocate_escrow(alice, alice, AmountType::from(19)).wait().unwrap();
    let ss = get_and_show_stake(&backend, alice, "Alice");
    assert_eq!(ss.total_stake, AmountType::from(100 - 10 - 5 - 17));
    assert_eq!(ss.escrowed, AmountType::from(13 + 19));

    debug!("taking some from self-escrow");
    backend
        .take_and_release_escrow(alice, self_escrow_id, AmountType::from(11))
        .wait()
        .unwrap();
    let ss = get_and_show_stake(&backend, alice, "Alice");
    assert_eq!(ss.total_stake, AmountType::from(100 - 10 - 5 - 17));
    assert_eq!(ss.escrowed, AmountType::from(13));
    // ----------------------------------------------------
    debug!("create escrow from alice to alice");
    let self_escrow_id = backend.allocate_escrow(alice, alice, AmountType::from(23)).wait().unwrap();
    let ss = get_and_show_stake(&backend, alice, "Alice");
    assert_eq!(ss.total_stake, AmountType::from(100 - 10 - 5 - 17));
    assert_eq!(ss.escrowed, AmountType::from(13 + 23));

    debug!("taking all from self-escrow");
    backend
        .take_and_release_escrow(alice, self_escrow_id, AmountType::from(23))
        .wait()
        .unwrap();
    let ss = get_and_show_stake(&backend, alice, "Alice");
    assert_eq!(ss.total_stake, AmountType::from(100 - 10 - 5 - 17));
    assert_eq!(ss.escrowed, AmountType::from(13));
    // ----------------------------------------------------
    debug!("create escrow from alice to alice");
    let self_escrow_id = backend.allocate_escrow(alice, alice, AmountType::from(29)).wait().unwrap();
    let ss = get_and_show_stake(&backend, alice, "Alice");
    assert_eq!(ss.total_stake, AmountType::from(100 - 10 - 5 - 17));
    assert_eq!(ss.escrowed, AmountType::from(13 + 29));

    debug!("taking none from self-escrow");
    backend
        .take_and_release_escrow(alice, self_escrow_id, AmountType::from(0))
        .wait()
        .unwrap();
    let ss = get_and_show_stake(&backend, alice, "Alice");
    assert_eq!(ss.total_stake, AmountType::from(100 - 10 - 5 - 17));
    assert_eq!(ss.escrowed, AmountType::from(13));
}
