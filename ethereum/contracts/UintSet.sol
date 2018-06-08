pragma solidity ^0.4.23;

contract UintSet {
  uint[] internal members;  // zero index location is not used.
  mapping(uint => uint) internal locations;

  constructor() public {
    members.push(0); // dummy value
  }
  // post-condition: members.length == 1, locations empty.

  function size() public view returns (uint num_elements) {
    num_elements = members.length - 1;
  }

  function get(uint ix) public view returns (uint datum) {
    datum = members[ix+1]; // out, enforcing no-zero element access
  }

  function isMember(uint _v) public view returns (bool is_contained) {
    is_contained = locations[_v] != 0;
  }

  function addEntry(uint _v) public {
    require(!isMember(_v));
    // _v \not\in locations; \forall i \in [0,members.length): members[i] \ne _v
    locations[_v] = members.length;
    members.push(_v);
    // _v \in locations; locations[_v] = members.length-1; members[members.length-1] = _v
  }

  function removeEntry(uint _v) public {
    // Remove entry in members array for _v by moving the last element there
    // and updating the mapping.
    require(isMember(_v));
    uint last = members[members.length - 1];
    uint v_pos = locations[_v];  // v_pos \in [0, members.length), so could be members.length - 1.
    members[v_pos] = last;
    locations[last] = v_pos;
    delete locations[_v];  // if _v was the last entry, this also removes it since swap was no-op.
    members.length--;
  }
}
