#!/usr/bin/env python3
"""
Demo script for Smart Contract Audit Tool
"""

import sys
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from smart_audit.core import AuditEngine, AuditResult, Severity
from analyzers.pattern_analyzer import PatternAnalyzer
from generators.report_generator import ReportGenerator
from generators.poc_generator import POCGenerator


def demo_basic_audit():
    """Demo: Basic audit flow"""
    print("\n" + "="*60)
    print("DEMO: Basic Audit Flow")
    print("="*60 + "\n")
    
    # Create a test contract
    test_dir = Path("./demo_contracts")
    test_dir.mkdir(exist_ok=True)
    
    test_contract = test_dir / "Vulnerable.sol"
    test_contract.write_text("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract VulnerableToken is ERC20 {
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() ERC20("Vulnerable", "VULN") {
        owner = msg.sender;
    }
    
    // Vulnerability 1: Reentrancy
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        
        balances[msg.sender] -= amount;
    }
    
    // Vulnerability 2: Missing access control
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
    
    // Vulnerability 3: Centralization
    function pause() public onlyOwner {
        // Owner can pause everything
    }
    
    // Vulnerability 4: tx.origin usage
    function authenticate() public {
        require(msg.sender == owner);
        // Uses tx.origin somewhere
    }
}
""")
    
    print("[*] Created test contract with vulnerabilities")
    
    # Run pattern analysis
    print("\n[*] Running pattern analysis...")
    analyzer = PatternAnalyzer()
    findings = analyzer.analyze_file(test_contract)
    
    print(f"[+] Found {len(findings)} issues:")
    for f in findings:
        print(f"    [{f.severity}] {f.pattern_name} at line {f.line}")
    
    # Generate report
    print("\n[*] Generating report...")
    output_dir = Path("./demo_output")
    reporter = ReportGenerator(output_dir)
    
    # Convert PatternMatch to Finding for the report
    from smart_audit.core import Finding
    
    converted_findings = []
    for f in findings:
        try:
            sev = Severity(f.severity.lower())
        except ValueError:
            sev = Severity.INFORMATIONAL
        
        converted_findings.append(Finding(
            id=f"DEMO-{len(converted_findings)+1:03d}",
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
    
    # Create mock result for demo
    result = AuditResult(
        repo_url="demo://local",
        commit="demo123",
        timestamp="2026-01-01T00:00:00Z",
        status="completed",
        total_contracts=1,
        total_lines=50,
        findings=converted_findings
    )
    
    json_file = reporter.generate_json(result)
    md_file = reporter.generate_markdown(result)
    html_file = reporter.generate_html(result)
    
    print(f"[+] Generated reports:")
    print(f"    JSON: {json_file}")
    print(f"    Markdown: {md_file}")
    print(f"    HTML: {html_file}")
    
    # Generate POCs
    print("\n[*] Generating POCs...")
    poc_dir = output_dir / "pocs"
    poc_gen = POCGenerator(poc_dir)
    
    for finding in converted_findings:
        if finding.severity.value in ['critical', 'high', 'medium']:
            poc_file = poc_gen.save_poc(finding, "VulnerableToken")
            print(f"    Generated: {poc_file.name}")
    
    # Cleanup
    test_contract.unlink()
    test_dir.rmdir()
    
    print("\n" + "="*60)
    print("DEMO COMPLETE")
    print("="*60)
    print(f"\nCheck {output_dir} for generated reports and POCs")


def demo_slither_analysis():
    """Demo: Slither integration"""
    print("\n" + "="*60)
    print("DEMO: Slither Analysis")
    print("="*60 + "\n")
    
    from analyzers.slither_analyzer import SlitherAnalyzer
    
    analyzer = SlitherAnalyzer()
    
    if analyzer.is_available():
        print("[+] Slither is available")
        print("[*] Note: Full Slither analysis requires a compilable project")
    else:
        print("[-] Slither not installed")
        print("    Install with: pip install slither-analyzer")


def main():
    """Run demos"""
    print("\n" + "#"*60)
    print("# SMART CONTRACT AUDIT TOOL - DEMO")
    print("#"*60)
    
    demo_basic_audit()
    demo_slither_analysis()
    
    print("\n\nDone!")


if __name__ == "__main__":
    main()
