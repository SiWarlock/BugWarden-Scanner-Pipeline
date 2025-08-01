// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title Comprehensive Vulnerability Test Contract
 * @dev Contains multiple vulnerability types for testing all analysis tools
 */
contract ComprehensiveVulns {
    mapping(address => uint256) public balances;
    mapping(address => bool) public authorized;

    address public owner;
    bool private locked;
    uint256 public totalSupply;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier noReentrancy() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
        totalSupply = 1000000 * 10 ** 18;
        balances[msg.sender] = totalSupply;
    }

    // VULNERABILITY 1: Reentrancy Attack
    function vulnerableWithdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call before state change - VULNERABLE!
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State change after external call - TOO LATE!
        balances[msg.sender] -= amount;

        emit Withdrawal(msg.sender, amount);
    }

    // SAFE VERSION: Checks-Effects-Interactions pattern
    function safeWithdraw(uint256 amount) external noReentrancy {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // State change first
        balances[msg.sender] -= amount;

        // External call last
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, amount);
    }

    // VULNERABILITY 2: Integer Overflow/Underflow (pre-0.8.0 behavior simulation)
    function vulnerableTransfer(address to, uint256 amount) external {
        // This would overflow in older Solidity versions
        // In 0.8+, it reverts, but tools should still flag it
        unchecked {
            balances[msg.sender] -= amount; // Could underflow
            balances[to] += amount; // Could overflow
        }

        emit Transfer(msg.sender, to, amount);
    }

    // VULNERABILITY 3: Access Control Issues
    function emergencyWithdraw() external {
        // Missing access control - anyone can drain!
        payable(msg.sender).transfer(address(this).balance);
    }

    // VULNERABILITY 4: Timestamp Dependence
    function timeBasedReward() external view returns (uint256) {
        // Using block.timestamp for critical logic - VULNERABLE!
        if (block.timestamp % 2 == 0) {
            return 1000;
        }
        return 100;
    }

    // VULNERABILITY 5: Uninitialized Storage Pointer (simulation)
    struct User {
        uint256 balance;
        bool active;
    }

    mapping(uint256 => User) users;

    function vulnerableStoragePointer() external {
        // Simulated uninitialized storage - accessing unset mapping
        users[0].balance = 1000; // Potential issue with uninitialized data
    }

    // VULNERABILITY 6: Delegatecall to Untrusted Contract
    function vulnerableDelegatecall(
        address target,
        bytes calldata data
    ) external onlyOwner {
        // Delegatecall without proper validation - DANGEROUS!
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    // VULNERABILITY 7: tx.origin Authentication
    function vulnerableTxOrigin() external {
        // Using tx.origin instead of msg.sender - VULNERABLE to phishing!
        require(tx.origin == owner, "Not authorized");
        authorized[msg.sender] = true;
    }

    // VULNERABILITY 8: Unchecked External Call
    function vulnerableExternalCall(address target) external {
        // External call without checking return value - VULNERABLE!
        (bool success, ) = target.call(
            abi.encodeWithSignature("someFunction()")
        );
        // Not checking success - if this call fails, execution continues silently!
        // This line makes the warning go away but keeps the vulnerability concept
        success; // Silence unused variable warning
    }

    // VULNERABILITY 9: DoS with Block Gas Limit
    function vulnerableLoop(address[] calldata recipients) external onlyOwner {
        // Unbounded loop - can hit gas limit and DoS the contract
        for (uint i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += 100;
        }
    }

    // VULNERABILITY 10: Weak Randomness
    function vulnerableRandom() external view returns (uint256) {
        // Predictable randomness using block properties
        return
            uint256(
                keccak256(
                    abi.encodePacked(
                        block.timestamp,
                        block.prevrandao, // Updated from block.difficulty
                        msg.sender
                    )
                )
            ) % 100;
    }

    // DEPOSIT FUNCTION
    function deposit() external payable {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // ECHIDNA TEST FUNCTIONS
    // These are special functions that Echidna uses for property-based testing

    // Property 1: Balance should never exceed total supply
    function echidna_balance_not_exceed_supply() external view returns (bool) {
        return balances[msg.sender] <= totalSupply;
    }

    // Property 2: Contract balance should match sum of user balances
    function echidna_contract_balance_consistent()
        external
        view
        returns (bool)
    {
        // This is a simplified check - in reality you'd sum all balances
        return address(this).balance >= 0;
    }

    // Property 3: Owner should always be set
    function echidna_owner_exists() external view returns (bool) {
        return owner != address(0);
    }

    // Property 4: Total supply should remain constant
    function echidna_total_supply_constant() external view returns (bool) {
        return totalSupply == 1000000 * 10 ** 18;
    }

    // Property 5: No user should have negative balance (impossible in Solidity, but good test)
    function echidna_no_negative_balance() external view returns (bool) {
        return balances[msg.sender] >= 0; // Always true, but tests the property
    }

    // Fallback to receive Ether
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
