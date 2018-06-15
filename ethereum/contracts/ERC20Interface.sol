pragma solidity ^0.4.23;

// ----------------------------------------------------------------------------
// ERC Token Standard #20 Interface
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
// ----------------------------------------------------------------------------
interface ERC20Interface {
  // public varible getters omitted: name, symbol, decimals, totalSupply.
  function balanceOf(address tokenOwner) external view returns (uint balance);
  function transfer(address to, uint tokens) external returns (bool success);
  function transferFrom(address from, address to, uint tokens) external returns (bool success);
  function approve(address spender, uint tokens) external returns (bool success);
  function allowance(address tokenOwner, address spender) external view returns (uint remaining);

  event Transfer(address indexed from, address indexed to, uint tokens);
  event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}
