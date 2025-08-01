// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Simple contract for testing Echidna
contract SimpleTest {
    uint256 private counter = 0;
    bool private flag = false;

    // Echidna should find a way to make this return false
    function echidna_test_always_true() public view returns (bool) {
        // This property says counter should always be less than 10
        return counter < 10;
    }

    // Function that Echidna can call to change state
    function increment(uint256 amount) public {
        // Bug: no bounds checking
        counter += amount;
    }

    // Another function for Echidna to explore
    function setFlag() public {
        if (counter > 5) {
            flag = true;
        }
    }

    // Property: flag should never be true when counter is even
    function echidna_test_flag_invariant() public view returns (bool) {
        if (flag && counter % 2 == 0) {
            return false; // Invariant violated
        }
        return true;
    }
}
