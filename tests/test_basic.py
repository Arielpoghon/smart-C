"""
Basic tests for Smart Contract Audit Tool
"""

import pytest
from pathlib import Path
from smart_audit.core import AuditEngine, Severity, Finding
from smart_audit.analyzers import PatternAnalyzer
from smart_audit.generators import ReportGenerator, POCGenerator


def test_severity_enum():
    """Test severity levels"""
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFORMATIONAL.value == "informational"


def test_finding_creation():
    """Test finding dataclass"""
    finding = Finding(
        id="TEST-001",
        title="Test Finding",
        severity=Severity.HIGH,
        category="test",
        file="test.sol",
        line=10,
        description="Test description",
        impact="Test impact",
        recommendation="Test recommendation"
    )
    
    assert finding.id == "TEST-001"
    assert finding.severity == Severity.HIGH


def test_pattern_analyzer():
    """Test pattern analyzer"""
    analyzer = PatternAnalyzer()
    
    # Create test file
    test_dir = Path("./test_contracts")
    test_dir.mkdir(exist_ok=True)
    
    test_file = test_dir / "test.sol"
    test_file.write_text("""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Test {
    function vulnerable() public {
        (bool success, ) = msg.sender.call{value: 1 ether}("");
    }
}
""")
    
    # Analyze
    findings = analyzer.analyze_file(test_file)
    
    # Should find reentrancy
    assert len(findings) > 0
    assert any(f.category == "reentrancy" for f in findings)
    
    # Cleanup
    test_file.unlink()
    test_dir.rmdir()


def test_report_generator(tmp_path):
    """Test report generation"""
    from smart_audit.core import AuditResult
    
    # Create mock result
    result = AuditResult(
        repo_url="https://github.com/test/repo",
        commit="abc123",
        timestamp="2026-01-01T00:00:00Z",
        status="completed",
        total_contracts=5,
        total_lines=1000
    )
    
    # Generate reports
    reporter = ReportGenerator(tmp_path)
    
    json_file = reporter.generate_json(result)
    assert json_file.exists()
    
    md_file = reporter.generate_markdown(result)
    assert md_file.exists()
    
    html_file = reporter.generate_html(result)
    assert html_file.exists()


def test_poc_generator(tmp_path):
    """Test POC generation"""
    from smart_audit.core import Finding, Severity
    
    finding = Finding(
        id="REENT-001",
        title="Reentrancy",
        severity=Severity.HIGH,
        category="reentrancy",
        file="test.sol",
        line=10,
        description="Test",
        impact="Test",
        recommendation="Test"
    )
    
    generator = POCGenerator(tmp_path)
    
    poc_file = generator.save_poc(finding, "TestContract")
    assert poc_file.exists()
    
    test_file = generator.save_foundry_test(finding, "TestContract")
    assert test_file.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
