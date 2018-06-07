pragma solidity ^0.4.23;

// The external ABI definition of the various epoch contracts, to be used to
// make calls against it.
contract EpochContract {
    function get_epoch(uint64) public view returns (uint64 epoch, uint64 since, uint64 till);
}
