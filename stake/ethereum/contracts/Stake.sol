pragma solidity ^0.4.23;

contract Stake {
  uint64 constant AMOUNT_MAX = ~uint64(0);
  uint constant UINT_MAX     = ~uint(0);

  struct StakeEscrowInfo {
    uint64 amount;  // Total stake
    uint64 escrowed;  // sum_{a \in accounts} escrow_map[a].amount

    uint[] escrows;
  }

  struct EscrowAccount {
    address owner;
    address target;
    uint64 amount;
  }

  StakeEscrowInfo[] accounts;  // zero index is never used
  EscrowAccount[] escrows;

  mapping(address => uint) stakes;

  constructor() public {
    StakeEscrowInfo memory dummy_stake;
    accounts.push(dummy_stake); // fill in zero index
    // depositStake(0xdeadbeef, initial_allocation);  // initial allocations
  }

  // should owner be replaced by msg.sender?  since this allows
  // creation of tokens, should this be a private method, invoked only
  // by the constructor?
  function depositStake(address owner, uint64 additional_stake) private {
    uint ix = stakes[owner];
    if (ix == 0) {
      StakeEscrowInfo memory entry;
      entry.amount = additional_stake;
      entry.escrowed = 0;
      stakes[owner] = accounts.length;
      accounts.push(entry); // copy to storage
      return;
    }
    require(AMOUNT_MAX - accounts[ix].amount >= additional_stake);
    // WouldOverflow
    accounts[ix].amount += additional_stake;
  }

  // Solidity does not allow returning a struct; we return the members individually.
  // To be able to return structs, we'd need to have to have at the top:
  // pragma experimental ABIEncoderV2; 
  function get_stake_status(address owner) public view returns (uint64 total_stake, uint64 escrowed) {
    uint id = stakes[owner];
    require(id != 0);
    total_stake = accounts[id].amount;
    escrowed = accounts[id].escrowed;
    return;
  }

  function transfer(address owner, address target, uint64 amount) public {
    uint owner_ix = stakes[owner];
    require(owner_ix != 0);
    // NoStakeAccount
    require(accounts[owner_ix].amount - accounts[owner_ix].escrowed >= amount);
    // InsufficentFunds
    uint target_ix = stakes[target];
    if (target_ix == 0) {
      StakeEscrowInfo memory entry;
      entry.amount = amount; // cannot overflow
      entry.escrowed = 0;
      accounts[owner_ix].amount -= amount;
      stakes[target] = accounts.length;
      accounts[target_ix] = entry;
      return;
    }
    require (accounts[target_ix].amount <= AMOUNT_MAX - amount);
    // WouldOverflow
    accounts[owner_ix].amount -= amount;
    accounts[target_ix].amount += amount;
  }

  // The function withdraw_stake destroys tokens. Not needed?

  // Remove sender from formal parameter list and use msg.sender?
  function allocate_escrow(address sender, address target, uint64 amount) public
    returns (uint escrow_id) {
    uint sender_ix = stakes[sender];
    require (sender_ix != 0);
    // NoStakeAccount
    require (accounts[sender_ix].amount - accounts[sender_ix].escrowed >= amount);
    // InsufficientFunds

    accounts[sender_ix].escrowed += amount;
    EscrowAccount memory ea;
    uint id = escrows.length;
    ea.owner = sender;
    ea.target = target;
    ea.amount = amount;
    escrows.push(ea);  // copies to storage
    accounts[sender_ix].escrows.push(id);
    return id;
  }

  // Remove sender from formal parameter list and use msg.sender?
  function list_active_escrows_iterator(address sender) public view
    returns (bool has_next, uint state) {
    uint sender_ix = stakes[sender];
    require(sender_ix != 0);
    has_next = accounts[sender_ix].escrows.length != 0;
    if (has_next) state = 0;
    else state = UINT_MAX;
  }

  function list_active_escrow_get(address sender, uint state) public view
    returns (uint id, address target, uint64 amount, bool has_next, uint next_state) {
    uint sender_ix = stakes[sender];
    require(sender_ix != 0);
    require(state < accounts[sender_ix].escrows.length);
    uint escrow_ix = accounts[sender_ix].escrows[state];
    require(escrow_ix < escrows.length);
    id = escrow_ix;
    target = escrows[escrow_ix].target;
    amount = escrows[escrow_ix].amount;
    if (state + 1 < accounts[sender_ix].escrows.length) {
      has_next = true;
      next_state = state + 1;
    } else {
      has_next = false;
      next_state = UINT_MAX;
    }
  }

  function fetch_escrow_by_id(uint escrow_id) public view
    returns (address owner, address target, uint64 amount) {
    owner = escrows[escrow_id].owner;
    target = escrows[escrow_id].target;
    amount = escrows[escrow_id].amount;
  }

  // Remove sender from formal parameter list and use msg.sender?
  function take_and_release_escrow(address sender, uint escrow_id, uint64 amount_requested) public {
    address owner = escrows[escrow_id].owner;  // NoEscrowAccount if previously deleted
    uint owner_ix = stakes[owner];
    require(owner_ix != 0);  // NoStakeAccount
    require(amount_requested <= escrows[escrow_id].amount); // RequestExceedsEscrowedFunds
    require(sender == escrows[escrow_id].target); // CallerNotEscrowTarget
    uint jx;
    uint num_escrows;

    uint sender_ix = stakes[sender];
    if (sender_ix == 0) {
      // create stake account for sender.
      StakeEscrowInfo memory entry;
      entry.amount = amount_requested;
      entry.escrowed = 0;
      accounts[owner_ix].amount -= amount_requested;
      accounts[owner_ix].escrowed -= escrows[escrow_id].amount;

      // Remove escrow id from escrows array in StakeEscrowInfo; invalides iterator.
      // If the number of escrow accounts per user is large, we could include a
      // mapping(uint => uint) to map from escrow_id to location in escrows where
      // it is located.
      num_escrows = accounts[owner_ix].escrows.length;
      for (jx = 0; jx < num_escrows; ++jx) {
	if (accounts[owner_ix].escrows[jx] == escrow_id) {
	  accounts[owner_ix].escrows[jx] = accounts[owner_ix].escrows[num_escrows - 1];
	  accounts[owner_ix].escrows.length -= 1;
	  break;
	}
      }

      stakes[sender] = accounts.length;
      accounts.push(entry); // copy to storage; create account for target
      delete escrows[escrow_id];
      return;
    }
    // check some invariants
    require(accounts[sender_ix].amount >= accounts[sender_ix].escrowed);
    require(accounts[sender_ix].escrowed >= escrows[escrow_id].amount);

    accounts[owner_ix].amount -= amount_requested;
    accounts[owner_ix].escrowed -= escrows[escrow_id].amount;

    num_escrows = accounts[owner_ix].escrows.length;
    for (jx = 0; jx < num_escrows; ++jx) {
      if (accounts[owner_ix].escrows[jx] == escrow_id) {
	accounts[owner_ix].escrows[jx] = accounts[owner_ix].escrows[num_escrows - 1];
	accounts[owner_ix].escrows.length -= 1;
	break;
      }
    }
    accounts[sender_ix].amount += amount_requested;

    delete escrows[escrow_id];
  }
}

