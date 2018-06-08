pragma solidity ^0.4.23;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

import "./ERC20Interface.sol";
import "./UintSet.sol";

// The Ekiden Stake token.  It is ERC20 compatible, but also includes
// the notion of escrow accounts in addition to allowances.  Escrow
// Accounts hold tokens that the stakeholder cannot use until the
// escrow account is closed.
contract Stake is ERC20Interface {
  // The convention used here is that contract input parameters are
  // prefixed with an underscore, and output parameters (in returns
  // list) are suffixed with an underscore.
  uint256 constant AMOUNT_MAX = ~uint256(0);

  event Burn(address indexed from, uint256 value);
  event EscrowClose(uint indexed escrow_id,
		    address indexed owner, uint256 value_returned,
		    address indexed target, uint256 value_claimed);

  struct StakeEscrowInfo {
    uint256 amount;  // Total stake, including inaccessible tokens
		     // that are in escrow.
    uint256 escrowed;  // sum_{a \in accounts} escrow_map[a].amount

    UintSet escrows;  // Set containing all the escrow account ids
		      // created by the stakeholder.

    // ERC20 allowances.  Unlike escrows, these permit an address to
    // transfer an amount without setting the tokens aside, so there
    // is no guarantee that the allowance amount would actually be
    // available when the entity with the allowance needs it.
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

  // ERC20 public variables; set once, at constract instantiation.
  string public name;
  string public symbol;
  uint8 public constant decimals = 18;
  uint256 public totalSupply;

  StakeEscrowInfo[] accounts;  // zero index is never used (mapping default)
  EscrowAccount[] escrows;  // zero index is never used

  mapping(address => uint) stakes;

  constructor(uint256 _initial_supply, string _tokenName, string _tokenSymbol) public {
    StakeEscrowInfo memory dummy_stake;
    accounts.push(dummy_stake); // fill in zero index
    EscrowAccount memory dummy_escrow;
    escrows.push(dummy_escrow); // fill in zero index
    totalSupply = _initial_supply * 10 ** uint256(decimals);
    _depositStake(msg.sender, totalSupply);
    name = _tokenName;
    symbol = _tokenSymbol;
  }

  function _addNewStakeEscrowInfo(address _addr, uint _amount, uint _escrowed) private
    returns (uint ix_) {
    require(stakes[_addr] == 0);
    StakeEscrowInfo memory entry;
    entry.amount = _amount;
    entry.escrowed = _escrowed;
    entry.escrows = new UintSet();
    ix_ = accounts.length;
    stakes[_addr] = ix_;
    accounts.push(entry);
  }

  function _depositStake(address _owner, uint256 _additional_stake) private {
    uint ix = stakes[_owner];
    if (ix == 0) {
      _addNewStakeEscrowInfo(_owner, _additional_stake, 0);
      return;
    }
    require(AMOUNT_MAX - accounts[ix].amount >= _additional_stake);
    // WouldOverflow
    accounts[ix].amount += _additional_stake;
  }

  // Solidity does not allow returning a struct; we return the members
  // individually.  To be able to return structs, we'd need to have to
  // have at the top: pragma experimental ABIEncoderV2;
  function getStakeStatus(address _owner) public view
    returns (uint256 total_stake_, uint256 escrowed_) {
    uint ix = stakes[_owner];
    require(ix != 0);
    total_stake_ = accounts[ix].amount;
    escrowed_ = accounts[ix].escrowed;
    return;
  }

  // This is really the available balance for a transferFrom
  // operation.  If we returned just the amount, then another
  // ERC20-compliant contract that checks balanceOf before using an
  // approval via transferFrom would encounter what would appear to be
  // an inconsistency: the transferFrom (read/write) is using what
  // should be the correct amount from the earlier returned value from
  // balanceOf (read), and within a transaction the balance could not
  // have decreased to make the transfer invalid.
  //
  // Use getStakeStatus for the details.
  function balanceOf(address _owner) public view returns (uint balance_) {
    uint ix = stakes[_owner];
    require(ix != 0);
    balance_ = accounts[ix].amount - accounts[ix].escrowed;
  }

  function _transfer(address _src, address _dst, uint256 _amount) private {
    uint src_ix = stakes[_src];
    require(src_ix != 0);
    // NoStakeAccount

    require(_amount <= accounts[src_ix].amount - accounts[src_ix].escrowed);
    // InsufficentFunds

    uint dst_ix = stakes[_dst];
    if (dst_ix == 0) {
      _addNewStakeEscrowInfo(_dst, _amount, 0);
      accounts[src_ix].amount -= _amount;
      emit Transfer(_src, _dst, _amount);
      return;
    }
    require(accounts[dst_ix].amount <= AMOUNT_MAX - _amount);
    // WouldOverflow
    accounts[src_ix].amount -= _amount;
    accounts[dst_ix].amount += _amount;
    emit Transfer(_src, _dst, _amount);
  }

  function transfer(address _target, uint256 _amount) public {
    _transfer(msg.sender, _target, _amount);
  }

  function transferFrom(address _from, address _to, uint256 _value) public returns (bool success_) {
    require(_to != 0x0);  // from ERC20: use Burn instead
    uint from_ix = stakes[_from];
    require(from_ix != 0);
    // NoStakeAccount
    uint to_ix = stakes[_to];
    if (to_ix == 0) {
      to_ix = _addNewStakeEscrowInfo(_to, 0, 0);
    }
    assert(to_ix != 0);
    // InternalError since _addNewStakeEscrowInfo should return non-zero index.

    require(_value <= accounts[from_ix].allowances[msg.sender]);
    // InsufficientAllowance

    require(_value <= accounts[from_ix].amount - accounts[from_ix].escrowed);
    // InsufficientFunds

    require(accounts[to_ix].amount <= AMOUNT_MAX - _value);
    // WouldOverflow

    accounts[from_ix].amount -= _value;
    accounts[to_ix].amount += _value;
    accounts[from_ix].allowances[msg.sender] -= _value;
    // Do not bother to delete mapping entry even if zeroed, since
    // there is a good chance that there will be another approval.
    success_ = true;
  }

  // ERC20 approve function.  This is idempotent.  Previous approval
  // is lost, not incremented.
  function approve(address _spender, uint256 _value) public returns (bool success_) {
    uint from_ix = stakes[msg.sender];
    require(from_ix != 0);
    accounts[from_ix].allowances[_spender] = _value;
    emit Approval(msg.sender, _spender, _value);
    success_ = true;
  }

  function approveAndCall(address _spender, uint256 _value, bytes _extraData) public
    returns (bool success_) {
    tokenRecipient spender = tokenRecipient(_spender);
    if (approve(_spender, _value)) {
      spender.receiveApproval(msg.sender, _value, this, _extraData);
      success_ = true;
    } else {
      success_ = false;
    }
  }

  function burn(uint256 _value) public returns (bool success_) {
    uint owner_ix = stakes[msg.sender];
    require(owner_ix != 0);
    require(_value <= accounts[owner_ix].amount - accounts[owner_ix].escrowed);
    accounts[owner_ix].amount -= _value;
    totalSupply -= _value;
    emit Burn(msg.sender, _value);
    success_ = true;
  }

  function burnFrom(address _from, uint256 _value) public returns (bool success_) {
    uint from_ix = stakes[_from];
    require(from_ix != 0);
    require(_value <= accounts[from_ix].allowances[msg.sender]);
    require(_value <= accounts[from_ix].amount - accounts[from_ix].escrowed);
    accounts[from_ix].allowances[msg.sender] -= _value;
    accounts[from_ix].amount -= _value;
    totalSupply -= _value;
    emit Burn(_from, _value);
    success_ = true;
  }

  function allocateEscrow(address target, uint256 amount) public returns (uint escrow_id_) {
    escrow_id_ = _allocateEscrow(msg.sender, target, amount);
  }

  function _allocateEscrow(address owner, address target, uint256 amount)
    private returns (uint escrow_id_) {
    uint owner_ix = stakes[owner];
    require (owner_ix != 0);
    // NoStakeAccount
    require (amount <= accounts[owner_ix].amount - accounts[owner_ix].escrowed);
    // InsufficientFunds

    accounts[owner_ix].escrowed += amount;
    EscrowAccount memory ea;
    ea.owner = owner;
    ea.target = target;
    ea.amount = amount;
    escrow_id_ = escrows.length;
    escrows.push(ea);  // copies to storage
    accounts[owner_ix].escrows.addEntry(escrow_id_);
  }

  // The information is publicly available in the blockchain, so we
  // might as well allow the public to get the information via an API
  // call, instead of reconstructing it from the blockchain.
  function listActiveEscrowsIterator(address owner) public view
    returns (bool has_next_, uint state_) {
    uint owner_ix = stakes[owner];
    require(owner_ix != 0);
    has_next_ = accounts[owner_ix].escrows.size() != 0;
    state_ = 0;
  }

  function listActiveEscrowGet(address _owner, uint _state) public view
    returns (uint id_, address target_, uint256 amount_,
	     bool has_next_, uint next_state_) {
    uint owner_ix = stakes[_owner];
    require(owner_ix != 0);
    require(_state < accounts[owner_ix].escrows.size());
    uint escrow_ix = accounts[owner_ix].escrows.get(_state);
    assert(escrow_ix != 0);
    assert(escrow_ix < escrows.length);
    assert(escrows[escrow_ix].owner == _owner);

    id_ = escrow_ix;
    target_ = escrows[escrow_ix].target;
    amount_ = escrows[escrow_ix].amount;

    next_state_ = _state + 1;
    has_next_ = next_state_ < accounts[owner_ix].escrows.size();
  }

  function fetchEscrowById(uint _escrow_id) public view
    returns (address owner_, address target_, uint256 amount_) {
    require(_escrow_id != 0);
    EscrowAccount memory ea = escrows[_escrow_id]; // copy to memory
    require(ea.owner != 0x0); // deleted escrow account will have zero address
    owner_ = ea.owner; // out
    target_ = ea.target; // out
    amount_ = ea.amount; // out
  }

  function takeAndReleaseEscrow(uint _escrow_id, uint256 _amount_requested) public {
    require(_escrow_id != 0);
    EscrowAccount memory ea = escrows[_escrow_id];
    require(ea.owner != 0x0);  // deleted escrow account will have zero address
    address owner = ea.owner;  // NoEscrowAccount if previously deleted
    uint owner_ix = stakes[owner];
    require(owner_ix != 0);  // NoStakeAccount
    require(_amount_requested <= ea.amount); // RequestExceedsEscrowedFunds
    uint amount_to_return = ea.amount - _amount_requested;
    require(msg.sender == ea.target); // CallerNotEscrowTarget

    uint sender_ix = stakes[msg.sender];
    if (sender_ix == 0) {
      sender_ix = _addNewStakeEscrowInfo(msg.sender, 0, 0);
    }

    // check some invariants
    require(ea.amount <= accounts[owner_ix].escrowed);
    require(accounts[owner_ix].escrowed <= accounts[owner_ix].amount);

    // require(amount_requested <= accounts[owner_ix].amount );
    // implies by
    //   _amount_requested <= ea.amount
    //                     <= accounts[owner_ix].escrowed
    //                     <= accounts[owner_ix].amount

    require(accounts[sender_ix].amount <= AMOUNT_MAX - _amount_requested);
    // WouldOverflow

    accounts[owner_ix].amount -= _amount_requested;
    accounts[owner_ix].escrowed -= ea.amount;
    accounts[owner_ix].escrows.removeEntry(_escrow_id);
    accounts[sender_ix].amount += _amount_requested;

    delete escrows[_escrow_id];
    emit EscrowClose(_escrow_id, owner, amount_to_return, msg.sender, _amount_requested);
  }
}

