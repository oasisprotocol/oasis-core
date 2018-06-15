pragma solidity ^0.4.23;

library UintSet {
  struct Data {
    uint[] members;  // zero index location is not used.
    mapping(uint => uint) locations;
    // mapping must be in storage; we cannot copy mappings between
    // memory and storage since mappings do not keep track of keys
  }

  /// Initialize the data structure.  Must be invoked before any other
  /// methods.  (Libraries do not have ctors.)
  function init(Data storage self) public {
    self.members.push(0); // dummy value
  }
  // post-condition: members.length == 1, locations empty.

  /// Returns the number of elements in the set.
  function size(Data storage self) public view returns (uint num_elements_) {
    num_elements_ = self.members.length - 1;
  }

  /// Gets an element stored in the set.  Users can iterate through
  /// all members by using as indices [0, ..., size()-1].
  function get(Data storage self, uint _ix) public view returns (uint datum_) {
    datum_ = self.members[_ix+1]; // out, enforcing no-zero element access
  }

  /// Predicate for whether a value _v is currently a member of the set.
  function isMember(Data storage self, uint _v) public view returns (bool is_contained_) {
    is_contained_ = self.locations[_v] != 0;
  }

  /// Add _v to the set.  Precondition: _v is not already a member of the set.
  function addEntry(Data storage self, uint _v) public {
    require(!isMember(self, _v));
    // _v \not\in locations; \forall i \in [0, self.members.length): self.members[i] \ne _v
    self.locations[_v] = self.members.length;
    self.members.push(_v);
    // post: _v \in locations; locations[_v] = self.members.length-1;
    // self.members[self.members.length-1] = _v
  }

  /// Remove _v from the set.  Precondition: _v is a member of the set.
  function removeEntry(Data storage self, uint _v) public {
    // Remove entry in members array for _v by moving the last element there
    // and updating the mapping.
    require(isMember(self, _v));
    uint last = self.members[self.members.length - 1];
    uint v_pos = self.locations[_v];
    // v_pos \in [0, self.members.length), so could be self.members.length - 1.
    self.members[v_pos] = last;
    self.locations[last] = v_pos;
    delete self.locations[_v];
    // if _v was the last entry, this also removes it since swap was no-op.
    self.members.length--;
  }
}
