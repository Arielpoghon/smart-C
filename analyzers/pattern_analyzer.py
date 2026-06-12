"""
Custom pattern-based vulnerability analyzer
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class PatternMatch:
    pattern_name: str
    severity: str
    category: str
    file: str
    line: int
    description: str
    impact: str
    recommendation: str
    code_snippet: str = ""
    references: List[str] = field(default_factory=list)


class PatternAnalyzer:
    """Custom pattern-based vulnerability detection"""
    
    # Vulnerability patterns with regex
    PATTERNS = {
        "reentrancy": {
            "patterns": [
                r'\.call\{.*\}\(.*\)',
                r'\.call\.value\(.*\)\(.*\)',
                r'\.send\(.*\)',
                r'\.transfer\(.*\)',
            ],
            "severity": "HIGH",
            "category": "reentrancy",
            "description": "External call detected without reentrancy protection",
            "impact": "Potential reentrancy attack",
            "recommendation": "Use nonReentrant modifier or checks-effects-interactions pattern"
        },
        "unchecked_return": {
            "patterns": [
                r'\.call\{.*\}\(.*\);$',
                r'\.send\(.*\);$',
            ],
            "severity": "MEDIUM",
            "category": "unchecked_return",
            "description": "Return value of external call not checked",
            "impact": "Failed calls could go unnoticed",
            "recommendation": "Always check return values of external calls"
        },
        "tx_origin": {
            "patterns": [
                r'tx\.origin',
            ],
            "severity": "HIGH",
            "category": "authentication",
            "description": "Use of tx.origin for authentication",
            "impact": "Phishing attacks via malicious contracts",
            "recommendation": "Use msg.sender instead of tx.origin"
        },
        "floating_pragma": {
            "patterns": [
                r'pragma solidity \^',
                r'pragma solidity >=',
            ],
            "severity": "LOW",
            "category": "configuration",
            "description": "Floating pragma version",
            "impact": "Contracts may be deployed with untested compiler version",
            "recommendation": "Lock pragma to specific version"
        },
        "timestamp_dependency": {
            "patterns": [
                r'block\.timestamp',
                r'now',
            ],
            "severity": "LOW",
            "category": "timestamp",
            "description": "Block timestamp usage detected",
            "impact": "Miners can manipulate timestamp within ~15 seconds",
            "recommendation": "Avoid using timestamp for critical logic"
        },
        "public_function": {
            "patterns": [
                r'function\s+\w+\s*\([^)]*\)\s+public\s+(?!view|pure)',
            ],
            "severity": "INFO",
            "category": "access_control",
            "description": "Public function without access control",
            "impact": "Anyone can call this function",
            "recommendation": "Add access control if needed"
        },
        "selfdestruct": {
            "patterns": [
                r'selfdestruct\(',
                r'suicide\(',
            ],
            "severity": "CRITICAL",
            "category": "destruction",
            "description": "Self-destruct function detected",
            "impact": "Contract can be destroyed, funds lost",
            "recommendation": "Remove selfdestruct or add strict access control"
        },
        "delegatecall": {
            "patterns": [
                r'\.delegatecall\(',
            ],
            "severity": "HIGH",
            "category": "delegatecall",
            "description": "Delegatecall usage detected",
            "impact": "Potential for arbitrary code execution",
            "recommendation": "Ensure target contract is trusted and verified"
        },
        "assembly": {
            "patterns": [
                r'assembly\s*\{',
            ],
            "severity": "INFO",
            "category": "assembly",
            "description": "Inline assembly usage",
            "impact": "Bypasses Solidity safety checks",
            "recommendation": "Ensure assembly code is correct and necessary"
        },
        "hardcoded_address": {
            "patterns": [
                r'address\(0x[0-9a-fA-F]{40}\)',
            ],
            "severity": "MEDIUM",
            "category": "configuration",
            "description": "Hardcoded address detected",
            "impact": "May not work on different networks",
            "recommendation": "Use constants or configuration"
        },
        "oracle_price_feed": {
            "patterns": [
                r'latestRoundData\(',
                r'getRoundData\(',
            ],
            "severity": "HIGH",
            "category": "oracle",
            "description": "Oracle price feed usage detected",
            "impact": "Price manipulation if oracle is compromised",
            "recommendation": "Add staleness checks and use multiple oracles"
        },
    }
    
    def __init__(self, custom_patterns: Optional[Dict] = None):
        self.patterns = {**self.PATTERNS}
        if custom_patterns:
            self.patterns.update(custom_patterns)
    
    def analyze_file(self, filepath: Path) -> List[PatternMatch]:
        """Analyze a single Solidity file"""
        findings = []
        
        try:
            content = filepath.read_text()
            lines = content.split('\n')
            
            for pattern_name, pattern_info in self.patterns.items():
                for regex in pattern_info["patterns"]:
                    for i, line in enumerate(lines, 1):
                        if re.search(regex, line):
                            # Get context
                            context_start = max(0, i - 3)
                            context_end = min(len(lines), i + 2)
                            context = '\n'.join(lines[context_start:context_end])
                            
                            finding = PatternMatch(
                                pattern_name=pattern_name,
                                severity=pattern_info["severity"],
                                category=pattern_info["category"],
                                file=str(filepath),
                                line=i,
                                description=pattern_info["description"],
                                impact=pattern_info["impact"],
                                recommendation=pattern_info["recommendation"],
                                code_snippet=context
                            )
                            findings.append(finding)
        
        except Exception as e:
            print(f"[!] Error analyzing {filepath}: {e}")
        
        return findings
    
    def analyze_directory(self, dir_path: Path) -> List[PatternMatch]:
        """Analyze all Solidity files in a directory"""
        findings = []
        
        for sol_file in dir_path.rglob("*.sol"):
            # Skip node_modules and lib
            if 'node_modules' in str(sol_file) or 'lib/' in str(sol_file):
                continue
            
            findings.extend(self.analyze_file(sol_file))
        
        return findings
    
    def get_pattern_summary(self) -> Dict[str, int]:
        """Get count of patterns by severity"""
        summary = {}
        for pattern in self.patterns.values():
            severity = pattern["severity"]
            summary[severity] = summary.get(severity, 0) + 1
        return summary
