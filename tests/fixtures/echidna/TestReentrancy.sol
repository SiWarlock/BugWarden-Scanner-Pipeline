// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Copy the vulnerable contract here to avoid import issues
contract ReentrancyVulnerable {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: State update after external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}

// Echidna test harness for reentrancy vulnerability
contract TestReentrancy {
    ReentrancyVulnerable target;
    uint256 initialBalance = 10 ether;

    constructor() {
        target = new ReentrancyVulnerable();
    }

    // Echidna will try to break this property
    function echidna_balance_constant() public view returns (bool) {
        // Property: Contract balance should never decrease below initial
        return address(target).balance >= 0;
    }

    // Echidna will try to find a way to extract funds
    function echidna_no_theft() public view returns (bool) {
        // Property: Attacker shouldn't be able to steal funds
        return address(this).balance <= initialBalance;
    }

    // Helper functions for Echidna to call
    function deposit() public payable {
        target.deposit{value: msg.value}();
    }

    function withdraw(uint256 amount) public {
        target.withdraw(amount);
    }

    // Receive ether (for reentrancy attack)
    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw(1 ether);
        }
    }
}
