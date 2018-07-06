pragma solidity ^0.4.23;

contract DisputeResolution {
	// Signature prefix (for web3.eth.sign compatibility).
	bytes constant SIGNATURE_PREFIX = "\x19Ethereum Signed Message:\n32";

	// The event emitted when a dispute is in progress.
	event OnDispute(
		bytes32 _batch_hash
	);

	// The event emitted when a dispute is resolved.
	event OnDisputeResolution(
		bytes32 _batch_hash,
		bytes32 _value
	);

	// The event emitted when a transition occurs.
	event OnTransition(
		uint64 _serial,
		bytes32 _finalized_root_hash
	);

	// DisputeResolution contract state.
	enum State {
		Invalid,
		Optimistic,
		Dispute
	}

	// A single node's role in a committee.
	enum Role {
		Invalid,
		Worker,
		Backup
	}

	// A single node's reveal.
	struct Reveal {
		Role role;
		bytes32 value;
	}

	// A per-epoch committee.
	struct Committee {
		// Committee members.
		address[] workers;
		address[] backups;

		// Revealed values for dispute/stake resolution.
		mapping(address => Reveal) reveals;

		address dispute_sender;
		bytes32 dispute_batch_hash;

		// Serial number for the finalized root hashes, starting from 0.
		uint64 serial;
	}

	// The contract owner.
	address public owner;

	// The current state.
	State public state;

	// The current committee.
	Committee public committee;

	// Construct a new DisputeResolution contract instance.
	constructor() public {
		owner = msg.sender;
	}

	function() public {
		revert();
	}

	modifier onlyMembersOrOwner() {
		require(
			(state == State.Invalid && msg.sender == owner) ||
			_is_member(msg.sender)
		);
		_;
	}

	modifier onlyWorkers() {
		require(_is_worker(msg.sender));
		_;
	}

	modifier onlyBackups() {
		require(_is_backup(msg.sender));
		_;
	}

	// Transition to a new committee.
	//
	// XXX: This *should* support bootstrapping from any entity rather
	// than being restricted to the contract owner for ease of testing.
	function transition(
		address[] _workers,
		address[] _backups,
		bytes32 _finalized_root_hash,
		bytes32[] _signatures_r,
		bytes32[] _signatures_s,
		bytes _signatures_v
	) external onlyMembersOrOwner() {
		require(_workers.length > 0);
		require(_backups.length > 0);

		// If the contract has been initialized, validate the signatures
		// with the current committee, otherwise accept the initial root
		// hash and committee (bootstrapping).
		if (state != State.Invalid) {
			// For now, attempting to transition committees mid-dispute
			// resolution is invalid.
			// dispute resolution state.
			require(state == State.Optimistic);

			bytes32 digest = derive_transition_digest(
				committee.serial,
				_workers,
				_backups,
				_finalized_root_hash
			);

			// WARNING: The validation obliterates the dispute state
			// if successful.
			_validate_transition_signatures(
				digest,
				_signatures_r,
				_signatures_s,
				_signatures_v
			);
		}

		_reset(true);

		// XXX: Query the registry contract to see if the new nodes
		// are actually members.

		// Store the new committee.
		committee.workers.length = _workers.length;
		committee.backups.length = _backups.length;
		for (uint i = 0; i < _workers.length; i++) {
			Reveal storage r = committee.reveals[_workers[i]];
			require(r.role == Role.Invalid);
			r.role = Role.Worker;

			committee.workers[i] = _workers[i];
		}
		for (i = 0; i < _backups.length; i++) {
			r = committee.reveals[_backups[i]];
			require(r.role == Role.Invalid);
			r.role = Role.Backup;

			committee.backups[i] = _backups[i];
		}

		state = State.Optimistic;
		emit OnTransition(committee.serial, _finalized_root_hash);
		committee.serial++;
	}

	// Submit a dispute.
	function dispute(
		bytes32 _batch_hash,
		bytes32[] _reveals,
		bytes32[] _signatures_r,
		bytes32[] _signatures_s,
		bytes _signatures_v
	) external onlyWorkers {
		require(state == State.Optimistic);
		require(
			_signatures_r.length == _signatures_s.length &&
			_signatures_s.length == _signatures_v.length &&
			_signatures_v.length == _reveals.length
		);
		require(_reveals.length > 0);

		// Prepare the mapping.
		_reset_reveals(committee.workers, false);

		// Handle the reveals.
		_handle_reveals(
			Role.Worker,
			_batch_hash,
			_reveals,
			_signatures_r,
			_signatures_s,
			_signatures_v
		);

		// Ensure that there either was at least one node missing or
		// at least one mismatch.
		if (_reveals.length == committee.workers.length) {
			uint matches = 0;
			for (uint i = 0; i < _reveals.length; i++) {
				if (_reveals[i] == _reveals[0]) {
					matches = matches + 1;
				}
			}
			require(matches < committee.workers.length);
		}

		state = State.Dispute;
		committee.dispute_sender = msg.sender;
		committee.dispute_batch_hash = _batch_hash;
		emit OnDispute(_batch_hash);
	}

	// Resolve a dispute.
	function resolve_dispute(
		bytes32[] _reveals,
		bytes32[] _signatures_r,
		bytes32[] _signatures_s,
		bytes _signatures_v
	) external onlyBackups {
		require(state == State.Dispute);
		require(
			_signatures_r.length == _signatures_s.length &&
			_signatures_s.length == _signatures_v.length &&
			_signatures_v.length == _reveals.length
		);
		require(_reveals.length > 0);

		// Prepare the mapping.
		_reset_reveals(committee.backups, false);

		// Handle the reveals.
		_handle_reveals(
			Role.Backup,
			committee.dispute_batch_hash,
			_reveals,
			_signatures_r,
			_signatures_s,
			_signatures_v
		);

		_resolve_dispute();
		state = State.Optimistic;
		_reset(false);
	}

	// Derive the digest that each node will sign when making the
	// `transition()` call.
	//
	// This can be called over web3, but if it is required to derive
	// this programatically elsewhere the digest is:
	//
	//   Keccak256(
	//     serial |
	//     uint32(len(workers)) | workers |
	//     uint32(len(backups)) | backups |
	//     finalized_root_state
	//   )
	function derive_transition_digest(
		uint64 _serial,
		address[] _workers,
		address[] _backups,
		bytes32 _finalized_root_hash
	) public pure returns (bytes32 digest_) {
		uint32 nr_workers = uint32(_workers.length);
		uint32 nr_backups = uint32(_backups.length);

		digest_ = keccak256(abi.encodePacked(
			_serial,
			nr_workers,
			_workers,
			nr_backups,
			_backups,
			_finalized_root_hash
		));
	}

	// Derive the digest that each node will sign when doing the commit/
	// reveal, that is also used for the `dispute()` and `resolve()` calls.
	//
	// This can be called over web3, but if it is required to derive
	// this programatically elsewhere the digest is:
	//
	//   Keccak256(serial | batch_hash | reveal)
	function derive_reveal_digest(
		uint64 _serial,
		bytes32 _batch_hash,
		bytes32 _reveal
	) public pure returns (bytes32 digest_) {
		digest_ = keccak256(abi.encodePacked(
			_serial,
			_batch_hash,
			_reveal
		));
	}

	function _is_member(address _addr) internal view returns (bool ok_) {
		ok_ = _is_worker(_addr) || _is_backup(_addr);
	}

	function _is_worker(address _addr) internal view returns (bool ok_) {
		require(state != State.Invalid);
		require(committee.workers.length > 0);

		ok_ = false;
		for (uint i = 0; i < committee.workers.length; i++) {
			if (_addr == committee.workers[i]) {
				ok_ = true;
				return;
			}
		}
	}

	function _is_backup(address _addr) internal view returns (bool ok_) {
		require(state != State.Invalid);
		require(committee.workers.length > 0);

		ok_ = false;
		for (uint i = 0; i < committee.backups.length; i++) {
			if (_addr == committee.backups[i]) {
				ok_ = true;
				return;
			}
		}
	}

	function _reset(bool _clear_role) internal {
		_reset_reveals(committee.workers, _clear_role);
		_reset_reveals(committee.backups, _clear_role);
		committee.dispute_batch_hash = bytes32(0);
		committee.dispute_sender = address(0);
	}

	function _reset_reveals(address[] _addrs, bool _clear_role) internal {
		for (uint i = 0; i < _addrs.length; i++) {
			Reveal storage r = committee.reveals[_addrs[i]];
			if (_clear_role) {
				r.role = Role.Invalid;
			}
			r.value = bytes32(0);
		}
	}

	function _validate_transition_signatures(
		bytes32 _digest,
		bytes32[] _signatures_r,
		bytes32[] _signatures_s,
		bytes _signatures_v
	) internal {
		require(
			_signatures_r.length == _signatures_s.length &&
			_signatures_s.length == _signatures_v.length
		);
		require(_signatures_r.length == committee.workers.length);

		// Prepare the mapping.
		_reset_reveals(committee.workers, false);

		// Validate that every expected address has signed
		// the digest.
		for (uint i = 0; i < _signatures_r.length; i++) {
			(bool ok, address addr) = _verify_split_signature(
				_signatures_r[i],
				_signatures_s[i],
				uint8(_signatures_v[i]),
				_digest
			);

			Reveal storage r = committee.reveals[addr];
			require(ok && r.role == Role.Worker);
			require(r.value == 0);

			r.value = _digest;
		}

		// Clean up.
		_reset_reveals(committee.workers, false);
	}

	function _handle_reveals(
		Role _expected_role,
		bytes32 _batch_hash,
		bytes32[] _reveals,
		bytes32[] _signatures_r,
		bytes32[] _signatures_s,
		bytes _signatures_v
	) internal {
		// WARNING: Caller is responsible for providing well formed
		// arguments.
		for (uint i = 0; i < _reveals.length; i++) {
			// HACK: This should "never" happen.
			require(_reveals[i] != 0);

			bytes32 digest = derive_reveal_digest(
				committee.serial,
				_batch_hash,
				_reveals[i]
			);

			(bool ok, address addr) = _verify_split_signature(
				_signatures_r[i],
				_signatures_s[i],
				uint8(_signatures_v[i]),
				digest
			);

			Reveal storage r = committee.reveals[addr];
			require(ok && r.role == _expected_role);
			require(r.value == 0);

			r.value = _reveals[i];
		}
	}

	function _resolve_dispute() internal {
		require(state == State.Dispute);

		// Figure out the reveal value after resolving the discrepancy.
		//
		// Avaliable information:
		//
		//   * `msg.sender` -> node that called `resolve()`.
		//   * `committee.dispute_sender` -> Node that called `dispute()`.
		//   * `committee.reveals` -> Every reveal value submitted to the
		//     `dispute()` and `resolve()` calls.
		//
		// nb: The state transition will happily happen if at least 1
		// reveal is present in either.
		//
		// `revert()`ing from here will result in the `resolve()` call
		// being reverted.
		//
		// TODO: This would be the logical location from which to
		// resolve stake.

		// XXX: For now, require that every single backup has come to
		// total consensus.
		bytes32 expected_value;
		for (uint i = 0; i < committee.backups.length; i++) {
			Reveal storage r = committee.reveals[committee.backups[i]];
			require(r.role == Role.Backup);
			if (i == 0) {
				require(r.value != 0);
				expected_value = r.value;
			} else {
				// Require total consensus.
				require(r.value == expected_value);
			}
		}

		emit OnDisputeResolution(committee.dispute_batch_hash, expected_value);
	}

	// Verify a signature over a 32 byte message, and recover/return the
	// signer's address iff the signature is valid.
	function _verify_split_signature(
		bytes32 _r,
		bytes32 _s,
		uint8 _v,
		bytes32 _message
	) internal pure returns (bool ok_, address addr_) {
		bytes32 sig_hash = keccak256(abi.encodePacked(
			SIGNATURE_PREFIX,
			_message
		));
		// web3.eth.sign and web3.accounts.sign disagree on how `v`
		// should be set.  See EIP-155.
		if (_v < 27) {
			_v += 27;
		}
		if (_v != 27 && _v != 28) {
			return (false, 0);
		}

		return (true, ecrecover(sig_hash, _v, _r, _s));
	}
}