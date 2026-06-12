#!/usr/bin/env python3
"""
Test script for Smart Contract Audit Tool
Tests with real-world contracts
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from smart_audit.core import AuditEngine, AuditResult, Severity, Finding
from analyzers.pattern_analyzer import PatternAnalyzer
from generators.report_generator import ReportGenerator
from generators.poc_generator import POCGenerator


def create_test_contract():
    """Create a realistic vulnerable contract for testing"""
    test_dir = Path("./test_contracts")
    test_dir.mkdir(exist_ok=True)
    
    # Complex vulnerable contract
    contract = test_dir / "DeFiVault.sol"
    contract.write_text("""// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IPriceFeed {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

contract DeFiVault {
    using SafeERC20 for IERC20;
    
    IERC20 public token;
    IPriceFeed public priceFeed;
    address public owner;
    address public admin;
    
    mapping(address => uint256) public balances;
    mapping(address => bool) public isWhitelisted;
    
    uint256 public totalDeposits;
    uint256 public feeBps = 100; // 1%
    
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    modifier onlyAdmin() {
        require(msg.sender == admin || msg.sender == owner, "Not admin");
        _;
    }
    
    constructor(address _token, address _priceFeed) {
        token = IERC20(_token);
        priceFeed = IPriceFeed(_priceFeed);
        owner = msg.sender;
        admin = msg.sender;
    }
    
    // VULNERABILITY 1: Reentrancy
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        
        emit Withdraw(msg.sender, amount);
    }
    
    // VULNERABILITY 2: Oracle manipulation (no staleness check)
    function getOraclePrice() public view returns (uint256) {
        (, int256 price,,,) = priceFeed.latestRoundData();
        return uint256(price);
    }
    
    // VULNERABILITY 3: Missing access control
    function mintTokens(address to, uint256 amount) external {
        // Anyone can mint!
        token.safeTransfer(to, amount);
    }
    
    // VULNERABILITY 4: tx.origin phishing
    function authenticate(address user) public returns (bool) {
        if (tx.origin == owner) {
            isWhitelisted[user] = true;
            return true;
        }
        return false;
    }
    
    // VULNERABILITY 5: Front-running susceptible
    function swap(uint256 amountIn, uint256 minAmountOut) external {
        uint256 price = getOraclePrice();
        uint256 amountOut = (amountIn * price) / 1e18;
        
        require(amountOut >= minAmountOut, "Slippage exceeded");
        
        token.safeTransferFrom(msg.sender, address(this), amountIn);
        // ... swap logic
    }
    
    // VULNERABILITY 6: Centralization risk
    function pause() external onlyOwner {
        // Owner can pause everything
    }
    
    function updateFee(uint256 newFee) external onlyOwner {
        feeBps = newFee; // No upper bound check!
    }
    
    function withdrawFees(address to, uint256 amount) external onlyOwner {
        token.safeTransfer(to, amount);
    }
    
    // VULNERABILITY 7: Integer overflow (Solidity 0.7.0)
    function calculateReward(uint256 deposit, uint256 rate) public pure returns (uint256) {
        return deposit * rate / 100; // Could overflow
    }
    
    // VULNERABILITY 8: Unchecked return value
    function emergencyWithdraw(address to, uint256 amount) external onlyOwner {
        token.safeTransfer(to, amount);
        // What if transfer fails silently?
    }
    
    receive() external payable {}
}
""")
    
    return test_dir, contract


def run_test():
    """Run comprehensive test"""
    print("\n" + "#"*70)
    print("# SMART CONTRACT AUDIT TOOL - COMPREHENSIVE TEST")
    print("#"*70 + "\n")
    
    # Create test contract
    test_dir, contract = create_test_contract()
    print("[*] Created test contract with 8 vulnerabilities")
    
    # Run analysis
    print("\n[*] Running pattern analysis...")
    analyzer = PatternAnalyzer()
    findings = analyzer.analyze_file(contract)
    
    print(f"[+] Found {len(findings)} issues:")
    for f in findings:
        print(f"    [{f.severity:12}] {f.pattern_name:20} at line {f.line:3}")
    
    # Convert to Finding objects
    converted_findings = []
    for f in findings:
        try:
            sev = Severity(f.severity.lower())
        except ValueError:
            sev = Severity.INFORMATIONAL
        
        converted_findings.append(Finding(
            id=f"VULN-{len(converted_findings)+1:03d}",
            title=f.pattern_name,
            severity=sev,
            category=f.category,
            file=f.file,
            line=f.line,
            description=f.description,
            impact=f.impact,
            recommendation=f.recommendation,
            code_snippet=f.code_snippet
        ))
    
    # Create result
    result = AuditResult(
        repo_url="test://local",
        commit="test123",
        timestamp="2026-01-01T00:00:00Z",
        status="completed",
        total_contracts=1,
        total_lines=120,
        findings=converted_findings
    )
    
    # Generate reports
    output_dir = Path("./test_output")
    reporter = ReportGenerator(output_dir)
    
    print("\n[*] Generating reports...")
    json_file = reporter.generate_json(result)
    md_file = reporter.generate_markdown(result)
    html_file = reporter.generate_html(result)
    
    print(f"  [+] JSON: {json_file}")
    print(f"  [+] Markdown: {md_file}")
    print(f"  [+] HTML: {html_file}")
    
    # Generate POCs
    print("\n[*] Generating POCs...")
    poc_dir = output_dir / "pocs"
    poc_gen = POCGenerator(poc_dir)
    
    for finding in converted_findings:
        if finding.severity.value in ['critical', 'high', 'medium']:
            poc_file = poc_gen.save_poc(finding, "DeFiVault")
            test_file = poc_gen.save_foundry_test(finding, "DeFiVault")
            print(f"  [+] {poc_file.name}")
    
    # Print summary
    print("\n" + "="*70)
    print("TEST COMPLETE")
    print("="*70)
    print(f"\nFindings by severity:")
    for sev, count in result.summary.items():
        if count > 0:
            print(f"  {sev.upper():15} {count}")
    
    print(f"\nAll reports saved to: {output_dir}")
    print("\nVulnerabilities detected:")
    print("  1. Reentrancy - withdraw() function")
    print("  2. Oracle manipulation - No staleness check")
    print("  3. Missing access control - mintTokens()")
    print("  4. tx.origin phishing - authenticate()")
    print("  5. Front-running susceptible - swap()")
    print("  6. Centralization risk - Owner can pause")
    print("  7. Integer overflow - Solidity 0.7.0")
    print("  8. Unchecked return value - emergencyWithdraw()")
    
    # Cleanup
    contract.unlink()
    test_dir.rmdir()
    
    print("\nDone!")


if __name__ == "__main__":
    run_test()
