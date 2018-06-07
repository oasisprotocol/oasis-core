pragma solidity ^0.4.23;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract UintSet {
  uint[] public values;  // zero index location is not used.
  mapping(uint => uint) locations;

  constructor() public {
    values.push(0); // dummy value
  }

  function size() public view returns (uint num_elements) {
    num_elements = values.length;
  }

  function get(uint ix) public view returns (uint datum) {
    datum = values[ix]; // out
  }

  function isMember(uint _v) public view returns (bool is_contained) {
    is_contained = locations[_v] != 0;
  }

  function addEntry(uint _v) public {
    require(!isMember(_v));
    locations[_v] = values.length;
    values.push(_v);
  }

  function removeEntry(uint _v) public {
    require(isMember(_v));
    uint last = values[values.length - 1];
    uint v_pos = locations[_v];
    values[v_pos] = last;
    locations[last] = v_pos;
    delete locations[_v];  // if _v is the last entry, this also removes it.
    values.length--;
  }
}

// The Ekiden Stake token.  It ERC20 compatible, but also includes the
// notion of escrow accounts in addition to allowances.  Escrow
// Accounts hold tokens that the stakeholder cannot use until the
// escrow account is closed.
contract Stake {
  uint256 constant AMOUNT_MAX = ~uint256(0);
  uint constant UINT_MAX     = ~uint(0);
  uint8 public constant decimals = 18;

  event Transfer(address indexed from, address indexed to, uint256 value);
  event Burn(address indexed from, uint256 value);
  event EscrowClose(uint indexed escrow_id,
		    address indexed owner, uint256 value_returned,
		    address indexed target, uint256 value_claimed);

  struct StakeEscrowInfo {
    uint256 amount;  // Total stake
    uint256 escrowed;  // sum_{a \in accounts} escrow_map[a].amount

    UintSet escrows;

    // ERC20 allowances.  Unlike escrows, these permit an address to
    // transfer an amount without setting the tokens aside, so there
    // is no guarantee that the allowance amount is actually
    // available.
    mapping(address => uint) allowances;
  }

  // Currently only the target may close the escrow account,
  // claiming/taking an amount that is at most the amount deposited
  // into the escrow account.
  struct EscrowAccount {
    address owner;
    address target;
    uint256 amount;
  }

  string public name;
  string public symbol;
  uint256 public total_supply;

  StakeEscrowInfo[] accounts;  // zero index is never used (mapping default)
  EscrowAccount[] escrows;  // zero index is never used

  mapping(address => uint) stakes;

  constructor(uint256 initial_supply, string tokenName, string tokenSymbol) public {
    StakeEscrowInfo memory dummy_stake;
    accounts.push(dummy_stake); // fill in zero index
    EscrowAccount memory dummy_escrow;
    escrows.push(dummy_escrow); // fill in zero index
    total_supply = initial_supply * 10 ** uint256(decimals);
    _depositStake(msg.sender, total_supply);
    name = tokenName;
    symbol = tokenSymbol;
  }

  function _addNewStakeEscrowInfo(address _addr, uint _amount, uint _escrowed) private
    returns (uint ix) {
    require(stakes[_addr] == 0);
    StakeEscrowInfo memory entry;
    entry.amount = _amount;
    entry.escrowed = _escrowed;
    entry.escrows = new UintSet();
    ix = accounts.length;  // out
    stakes[_addr] = ix;
    accounts.push(entry);
  }

  function _depositStake(address _owner, uint256 _additional_stake) private {
    uint ix = stakes[_owner];
    if (ix == 0) {
      ix = _addNewStakeEscrowInfo(_owner, _additional_stake, 0);
      return;
    }
    require(AMOUNT_MAX - accounts[ix].amount >= _additional_stake);
    // WouldOverflow
    accounts[ix].amount += _additional_stake;
  }

  // Solidity does not allow returning a struct; we return the members
  // individually.  To be able to return structs, we'd need to have to
  // have at the top: pragma experimental ABIEncoderV2;
  function get_stake_status(address owner) public view
    returns (uint256 total_stake, uint256 escrowed) {
    uint id = stakes[owner];
    require(id != 0);
    total_stake = accounts[id].amount; // out
    escrowed = accounts[id].escrowed; // out
    return;
  }

  function _transfer(address src, address dst, uint256 amount) private {
    uint src_ix = stakes[src];
    require(src_ix != 0);
    // NoStakeAccount
    require(accounts[src_ix].amount - accounts[src_ix].escrowed >= amount);
    // InsufficentFunds
    uint dst_ix = stakes[dst];
    if (dst_ix == 0) {
      dst_ix = _addNewStakeEscrowInfo(dst, 0, 0);
    }
    require (accounts[dst_ix].amount <= AMOUNT_MAX - amount);
    // WouldOverflow
    emit Transfer(src, dst, amount);
    accounts[src_ix].amount -= amount;
    accounts[dst_ix].amount += amount;
  }

  function transfer(address target, uint256 amount) public {
    _transfer(msg.sender, target, amount);
  }

  function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
    require(_to != 0x0);  // from ERC20: use Burn instead
    uint from_ix = stakes[_from];
    require(from_ix != 0);
    // NoStakeAccount
    uint to_ix = stakes[_to];
    if (to_ix == 0) {
      to_ix = _addNewStakeEscrowInfo(_to, 0, 0);
    }
    require(to_ix != 0);
    // InternalError since _addNewStakeEscrowInfo should return non-zero index.
    require(accounts[from_ix].allowances[msg.sender] >= _value);
    // InsufficientAllowance
    require(accounts[from_ix].amount - accounts[from_ix].escrowed >= _value);
    // InsufficientFunds
    require(accounts[to_ix].amount <= AMOUNT_MAX - _value);
    // WouldOverflow
    accounts[from_ix].amount -= _value;
    accounts[to_ix].amount += _value;
    accounts[from_ix].allowances[msg.sender] -= _value;
    // Do not bother to delete mapping entry even if zeroed, since
    // there is a good chance that there will be another approval.
    success = true; // out
  }

  // ERC20 approve function.  This is idempotent.  Previous approval
  // is lost, not incremented.
  function approve(address _spender, uint256 _value) public returns (bool success) {
    uint from_ix = stakes[msg.sender];
    require(from_ix != 0);
    accounts[from_ix].allowances[_spender] = _value;
    success = true; // out
  }

  function approveAndCall(address _spender, uint256 _value, bytes _extraData) public
    returns (bool success) {
    tokenRecipient spender = tokenRecipient(_spender);
    if (approve(_spender, _value)) {
      spender.receiveApproval(msg.sender, _value, this, _extraData);
      return true;
    }
    return false;
  }

  function burn(uint256 _value) public returns (bool success) {
    uint owner_ix = stakes[msg.sender];
    require(owner_ix != 0);
    require(accounts[owner_ix].amount - accounts[owner_ix].escrowed >= _value);
    accounts[owner_ix].amount -= _value;
    total_supply -= _value;
    success = true; // out
  }

  function burnFrom(address _from, uint256 _value) public returns (bool success) {
    uint from_ix = stakes[_from];
    require(from_ix != 0);
    require(accounts[from_ix].allowances[msg.sender] >= _value);
    require(accounts[from_ix].amount - accounts[from_ix].escrowed >= _value);
    accounts[from_ix].allowances[msg.sender] -= _value;
    accounts[from_ix].amount -= _value;
    emit Burn(_from, _value);
    success = true; // out
  }

  // The function withdraw_stake destroys tokens. Not needed?

  function allocate_escrow(address target, uint256 amount) public {
    _allocate_escrow(msg.sender, target, amount);
  }

  function _allocate_escrow(address owner, address target, uint256 amount)
    private returns (uint escrow_id) {
    uint owner_ix = stakes[owner];
    require (owner_ix != 0);
    // NoStakeAccount
    require (accounts[owner_ix].amount - accounts[owner_ix].escrowed >= amount);
    // InsufficientFunds

    accounts[owner_ix].escrowed += amount;
    EscrowAccount memory ea;
    ea.owner = owner;
    ea.target = target;
    ea.amount = amount;
    escrow_id = escrows.length; // out
    escrows.push(ea);  // copies to storage
    accounts[owner_ix].escrows.addEntry(escrow_id);
  }

  // The information is publicly available in the blockchain, so we
  // might as well allow the public to get the information via an API
  // call, instead of reconstructing it from the blockchain.
  function list_active_escrows_iterator(address owner) public view
    returns (bool has_next, uint state) {
    uint owner_ix = stakes[owner];
    require(owner_ix != 0);
    has_next = accounts[owner_ix].escrows.size() != 0; // out
    if (has_next) state = 0; // out
    else state = UINT_MAX; // out
  }

  function list_active_escrow_get(address owner, uint state) public view
    returns (uint id, address target, uint256 amount,
	     bool has_next, uint next_state) {
    uint owner_ix = stakes[owner];
    require(owner_ix != 0);
    require(state < accounts[owner_ix].escrows.size());
    uint escrow_ix = accounts[owner_ix].escrows.get(state);
    require(escrow_ix != 0);
    require(escrow_ix < escrows.length);

    id = escrow_ix; // out
    target = escrows[escrow_ix].target; // out
    amount = escrows[escrow_ix].amount; // out

    if (state + 1 < accounts[owner_ix].escrows.size()) {
      has_next = true; // out
      next_state = state + 1; // out
    } else {
      has_next = false; // out
      next_state = UINT_MAX; // out
    }
  }

  function fetch_escrow_by_id(uint escrow_id) public view
    returns (address owner, address target, uint256 amount) {
    owner = escrows[escrow_id].owner; // out
    target = escrows[escrow_id].target; // out
    amount = escrows[escrow_id].amount; // out
  }

  function take_and_release_escrow(uint escrow_id, uint256 amount_requested) public {
    address owner = escrows[escrow_id].owner;  // NoEscrowAccount if previously deleted
    uint owner_ix = stakes[owner];
    require(owner_ix != 0);  // NoStakeAccount
    require(amount_requested <= escrows[escrow_id].amount); // RequestExceedsEscrowedFunds
    uint amount_to_return = escrows[escrow_id].amount - amount_requested;
    require(msg.sender == escrows[escrow_id].target); // CallerNotEscrowTarget

    uint sender_ix = stakes[msg.sender];
    if (sender_ix == 0) {
      sender_ix = _addNewStakeEscrowInfo(msg.sender, 0, 0);
    }

    // check some invariants
    require(escrows[escrow_id].amount <= accounts[sender_ix].escrowed);
    require(accounts[sender_ix].escrowed <= accounts[sender_ix].amount);

    // require(amount_requested <= accounts[owner_ix].amount );
    // implies by
    //   amount_requested <= escrows[escrow_id].amount
    //                    <= accounts[sender_ix].escrowed
    //                    <= accounts[sender_ix].amount

    require(accounts[sender_ix].amount <= AMOUNT_MAX - amount_requested);
    // WouldOverflow

    accounts[owner_ix].amount -= amount_requested;
    accounts[owner_ix].escrowed -= escrows[escrow_id].amount;
    accounts[owner_ix].escrows.removeEntry(escrow_id);
    accounts[sender_ix].amount += amount_requested;

    delete escrows[escrow_id];
    emit EscrowClose(escrow_id, owner, amount_to_return, msg.sender, amount_requested);
  }
}

