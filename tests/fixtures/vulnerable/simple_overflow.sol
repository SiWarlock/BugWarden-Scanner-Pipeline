// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleOverflow {
    uint8 public count = 255;

    // VULNERABILITY: Integer overflow (though Solidity 0.8+ has built-in checks)
    function increment() public {
        count = count + 1; // This would overflow in older versions
    }

    // VULNERABILITY: Unchecked arithmetic allows overflow
    function unsafeIncrement() public {
        unchecked {
            count = count + 1; // This can overflow even in 0.8+
        }
    }
}
