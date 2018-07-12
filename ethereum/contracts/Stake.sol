pragma solidity ^0.4.23;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

import "./ERC20Interface.sol";

// The Ekiden Stake token.  It is ERC20 compatible, but also includes
// the notion of escrow in addition to allowances.  Escrow holds tokens
// that the stakeholder cannot use until the escrow is closed.
contract Stake is ERC20Interface {
  // The convention used here is that contract input parameters are
  // prefixed with an underscore, and output parameters (in returns
  // list) are suffixed with an underscore.

  // Maximum amount of stake that an account can hold.
  uint256 constant AMOUNT_MAX = ~uint256(0);

  event Burn(address indexed from, uint256 value);

  // This event is emitted when new escrow is added for the given owner.
  event EscrowAdd(address indexed owner,
                  uint256 amount_added);
  // This event is emitted when a part of the escrow is taken away from the owner.
  event EscrowTake(address indexed owner,
                   uint256 amount_taken);
  // This event is emitted when the remaining escrow is released back to the owner.
  event EscrowRelease(address indexed owner,
                      uint256 amount_returned);

  struct StakeEscrowInfo {
    uint256 amount;  // Total stake, including inaccessible tokens
                     // that are in escrow.
    uint256 escrowed;  // Tokens in escrow.

    // ERC20 allowances.  Unlike escrow, these permit an address to
    // transfer an amount without setting the tokens aside, so there
    // is no guarantee that the allowance amount would actually be
    // available when the entity with the allowance needs it.
    mapping(address => uint) allowances;
  }

  // ERC20 public variables; set once, at constract instantiation.
  string public name;
  string public symbol;
  uint8 public constant decimals = 18;
  uint256 public totalSupply;

  StakeEscrowInfo[] accounts;  // zero index is never used (mapping default)

  // Mapping `stakes` maps Ethereum address to index in `accounts` array.
  mapping(address => uint) stakes;

  // Hardcoded addresses for the DisputeResolution and EntityRegistry contracts.
  // Only the DisputeResolution can call `takeEscrow` and only the
  // EntityRegistry can call `releaseEscrow`, so we need to have their
  // addresses to check that.
  address dr_contract_addr;
  address registry_contract_addr;

  constructor(uint256 _initial_supply, string _tokenName, string _tokenSymbol) public {
    StakeEscrowInfo memory dummy_stake;
    accounts.push(dummy_stake); // fill in zero index
    totalSupply = _initial_supply * 10 ** uint256(decimals);
    _depositStake(msg.sender, totalSupply);
    name = _tokenName;
    symbol = _tokenSymbol;

    // At initialization, the DisputeResolution and EntityRegistry contracts
    // also depend on us being already initialized, so we can't have their
    // addresses here, but they have to be set later using
    // `linkToDisputeResolution` and `linkToEntityRegistry`.
    dr_contract_addr = 0;
    registry_contract_addr = 0;
  }

  function() public {
    revert();
  }

  // Tell the Stake contract on which address the DisputeResolution contract
  // was deployed on.  This can only be done once.
  function linkToDisputeResolution(address _dr_contract_addr) public returns (bool success_) {
    require(dr_contract_addr == 0);
    dr_contract_addr = _dr_contract_addr;
    success_ = true;
  }

  // Tell the Stake contract on which address the EntityRegistry contract
  // was deployed on.  This can only be done once.
  function linkToEntityRegistry(address _registry_contract_addr) public returns (bool success_) {
    require(registry_contract_addr == 0);
    registry_contract_addr = _registry_contract_addr;
    success_ = true;
  }

  function _addNewStakeEscrowInfo(address _addr, uint256 _amount, uint256 _escrowed) private
    returns (uint ix_) {
    require(stakes[_addr] == 0);
    StakeEscrowInfo memory entry;
    entry.amount = _amount;
    entry.escrowed = _escrowed;
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
  function getStakeStatus(address _owner) external view
    returns (uint256 total_stake_, uint256 escrowed_) {
    uint ix = stakes[_owner];
    if (ix == 0) {
      total_stake_ = 0;
      escrowed_ = 0;
    } else {
      total_stake_ = accounts[ix].amount;
      escrowed_ = accounts[ix].escrowed;
    }
    return;
  }

  // This is really the available balance for a transfer or
  // transferFrom operation.  If we returned just the amount, then
  // another ERC20-compliant contract that checks balanceOf before
  // using an approval via transferFrom would encounter what would
  // appear to be an inconsistency: the transferFrom (read/write) is
  // using what should be the correct amount from the earlier returned
  // value from balanceOf (read), and within a transaction the balance
  // could not have decreased to make the transfer invalid.
  //
  // NB: if _owner is invalid, we return zero because other ERC20
  // tokens do so: they just have a mapping(address => uint256), so
  // will return zero.  We emulate this instead of aborting the
  // transaction.
  //
  // Use getStakeStatus for the details.
  function balanceOf(address _owner) external view returns (uint balance_) {
    uint ix = stakes[_owner];
    if (ix == 0) {
      balance_ = 0; // safe to query any account w/o aborting transaction
    } else {
      balance_ = accounts[ix].amount - accounts[ix].escrowed;
    }
  }

  // ERC20 definition allows contract method to revert or return with
  // success_ == false. It warns users of transfer and transferFrom
  // that one *must* check the returned result.
  //
  // Having success_ out parameter makes it easier for contracts to
  // try to do the transfer, rather than to do balanceOf before
  // attempting the transfer.  However, if _some_ contracts revert and
  // some return success_ = false, then contracts that use the ERC20
  // interface *must* use balanceOf to check ahead of time rather than
  // be able to rely on the returned success_ status.
  //
  // Example implementations such as
  //
  // https://github.com/OpenZeppelin/openzeppelin-solidity/blob/master/contracts/token/ERC20/BasicToken.sol
  //
  // uses require(..) to check for insufficient funds.  This means
  // that there are likely to be ERC20 contracts in-the-wild that does
  // the same.
  //
  // Since truffle makes it difficult to test the returned value of a
  // contract call that actually performs a transaction -- requiring
  // instead that the code generate an event (which in this case
  // exists, but in some cases would be a test-only event), we just
  // make all conditions that would have returned with success_ =
  // false revert the transaction.  We could rely on the event in our
  // tests, but then we would have no way to test verify whether the
  // event is generated if-and-only-if the transaction succeeds.
  function _transfer(address _src, address _dst, uint256 _amount) private
    returns (bool success_) {
    uint src_ix = stakes[_src];
    require(src_ix != 0);
    // NoStakeAccount

    require(_amount <= accounts[src_ix].amount - accounts[src_ix].escrowed);
    // InsufficentFunds

    uint dst_ix = stakes[_dst];
    if (dst_ix == 0) {
      dst_ix = _addNewStakeEscrowInfo(_dst, _amount, 0);
      require(dst_ix != 0);
      accounts[src_ix].amount -= _amount;
      emit Transfer(_src, _dst, _amount);
      success_ = true;
      return;
    }
    require(accounts[dst_ix].amount <= AMOUNT_MAX - _amount);
    // WouldOverflow
    accounts[src_ix].amount -= _amount;
    accounts[dst_ix].amount += _amount;
    emit Transfer(_src, _dst, _amount);
    success_ = true;
  }

  function transfer(address _target, uint256 _amount) external returns (bool success_) {
    success_ = _transfer(msg.sender, _target, _amount);
  }

  function transferFrom(address _from, address _to, uint _value) external returns (bool success_) {
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
    emit Transfer(_from, _to, _value);
    success_ = true;
  }

  // ERC20 approve function.  This is idempotent.  Previous approval
  // is lost, not incremented.
  function approve(address _spender, uint256 _value) public returns (bool success_) {
    uint from_ix = stakes[msg.sender];
    if (from_ix == 0) {
      from_ix = _addNewStakeEscrowInfo(msg.sender, 0, 0);
    }
    accounts[from_ix].allowances[_spender] = _value;
    emit Approval(msg.sender, _spender, _value);
    success_ = true;
  }

  function approveAndCall(address _spender, uint256 _value, bytes _extraData) external
    returns (bool success_) {
    tokenRecipient spender = tokenRecipient(_spender);
    if (approve(_spender, _value)) {
      spender.receiveApproval(msg.sender, _value, this, _extraData);
      success_ = true;
    } else {
      success_ = false;
    }
  }

  function allowance(address _owner, address _spender) external view returns (uint256 remaining_) {
    uint owner_ix = stakes[_owner];
    if (owner_ix == 0) {
      remaining_ = 0; // safe to call for arbitrary owner
    } else {
      remaining_ = accounts[owner_ix].allowances[_spender];
    }
  }

  function burn(uint256 _value) external returns (bool success_) {
    uint owner_ix = stakes[msg.sender];
    require(owner_ix != 0);
    require(_value <= accounts[owner_ix].amount - accounts[owner_ix].escrowed);
    accounts[owner_ix].amount -= _value;
    totalSupply -= _value;
    emit Burn(msg.sender, _value);
    success_ = true;
  }

  function burnFrom(address _from, uint256 _value) external returns (bool success_) {
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

  function addEscrow(uint256 _amount) external returns (uint256 total_escrow_so_far_) {
    total_escrow_so_far_ = _addEscrow(msg.sender, _amount);
    emit EscrowAdd(msg.sender, _amount);
  }

  function _addEscrow(address _owner, uint256 _amount) private returns (uint256 total_escrow_so_far_) {
    uint owner_ix = stakes[_owner];
    require (owner_ix != 0);
    // NoStakeAccount
    require (_amount <= accounts[owner_ix].amount - accounts[owner_ix].escrowed);
    // InsufficientFunds

    accounts[owner_ix].escrowed += _amount;

    total_escrow_so_far_ = accounts[owner_ix].escrowed;
  }

  // The information is publicly available in the blockchain, so we
  // might as well allow the public to get the information via an API
  // call, instead of reconstructing it from the blockchain.
  function fetchEscrowAmount(address _owner) external view returns (uint256 total_escrow_so_far_) {
    uint owner_ix = stakes[_owner];
    require(owner_ix != 0);

    total_escrow_so_far_ = accounts[owner_ix].escrowed;
  }

  function takeEscrow(address _owner, uint256 _amount_requested) external returns (uint256 amount_taken_) {
    // Only the DisputeResolution contract may take escrow.
    require(msg.sender == dr_contract_addr);

    // Set up a stake account for DisputeResolution if it doesn't have one yet.
    uint dispute_resolution_ix = stakes[msg.sender];
    if (dispute_resolution_ix == 0) {
      dispute_resolution_ix = _addNewStakeEscrowInfo(msg.sender, 0, 0);
    }

    uint owner_ix = stakes[_owner];
    require(owner_ix != 0);
    require(_amount_requested <= accounts[owner_ix].escrowed); // RequestExceedsEscrowedFunds

    // Check invariants.
    require(accounts[owner_ix].escrowed <= accounts[owner_ix].amount);
    require(accounts[dispute_resolution_ix].amount <= AMOUNT_MAX - _amount_requested); // WouldOverflow

    // Take the escrowed stake from the owner's account and deposit it
    // in the DisputeResolution contract's account.
    accounts[owner_ix].amount -= _amount_requested;
    accounts[owner_ix].escrowed -= _amount_requested;
    accounts[dispute_resolution_ix].amount += _amount_requested;

    amount_taken_ = _amount_requested;
    emit EscrowTake(_owner, _amount_requested);
  }

  function releaseEscrow(address _owner) external returns (uint256 amount_returned_) {
    // Only the EntityRegistry contract may release escrow.
    require(msg.sender == registry_contract_addr);

    uint owner_ix = stakes[_owner];
    require(owner_ix != 0);

    // Check invariants.
    require(accounts[owner_ix].escrowed <= accounts[owner_ix].amount);

    // The remainder of the escrow is released back to the owner.
    uint256 amount_returned = accounts[owner_ix].escrowed;
    accounts[owner_ix].escrowed = 0;

    amount_returned_ = amount_returned;
    emit EscrowRelease(_owner, amount_returned);
  }
}

