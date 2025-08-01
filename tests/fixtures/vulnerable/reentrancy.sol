// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // VULNERABILITY: Reentrancy - state update after external call
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call before state update (vulnerable to reentrancy)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update after external call
        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);
    }

    // Safe version for comparison
    function safeWithdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // State update before external call (safe)
        balances[msg.sender] -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, amount);
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
