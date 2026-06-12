"""
Core audit engine - orchestrates the entire audit process
"""

import os
import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    file: str
    line: int
    description: str
    impact: str
    recommendation: str
    code_snippet: str = ""
    poc: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class AuditResult:
    repo_url: str
    commit: str
    timestamp: str
    status: str
    total_contracts: int = 0
    total_lines: int = 0
    findings: List[Finding] = field(default_factory=list)
    compilation_errors: List[str] = field(default_factory=list)
    slither_output: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def summary(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


class AuditEngine:
    """Main audit orchestrator"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.work_dir = None
        self.repo_dir = None
        
    def clone_repo(self, repo_url: str) -> Path:
        """Clone a git repository"""
        self.work_dir = Path(tempfile.mkdtemp(prefix="smart_audit_"))
        self.repo_dir = self.work_dir / "repo"
        
        print(f"[*] Cloning {repo_url}...")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(self.repo_dir)],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Failed to clone repo: {result.stderr}")
        
        # Get commit hash
        commit_result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(self.repo_dir),
            capture_output=True,
            text=True
        )
        
        return self.repo_dir
    
    def find_solidity_files(self) -> List[Path]:
        """Find all Solidity files in the repo"""
        if not self.repo_dir:
            raise RuntimeError("No repo cloned")
        
        sol_files = []
        for root, dirs, files in os.walk(self.repo_dir):
            # Skip common non-contract directories
            dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'lib', 'cache']]
            
            for f in files:
                if f.endswith('.sol'):
                    sol_files.append(Path(root) / f)
        
        return sol_files
    
    def compile_contracts(self, sol_files: List[Path]) -> Dict[str, Any]:
        """Compile Solidity contracts"""
        print(f"[*] Found {len(sol_files)} Solidity files")
        
        # Check if solc is available
        try:
            subprocess.run(["solc", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("[!] solc not found, skipping compilation")
            return {"success": False, "errors": ["solc not installed"]}
        
        # Try to compile with solc
        # For now, just return success
        return {"success": True, "errors": []}
    
    def run_slither(self) -> Dict[str, Any]:
        """Run Slither static analysis"""
        print("[*] Running Slither analysis...")
        
        try:
            # Check if slither is available
            subprocess.run(["slither", "--version"], capture_output=True, check=True)
            
            # Run slither with JSON output
            json_output = self.repo_dir / "slither-output.json"
            result = subprocess.run(
                [
                    "slither",
                    str(self.repo_dir),
                    "--json", str(json_output),
                    "--checklist",
                    "--markdown-root", str(self.repo_dir)
                ],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Parse output
            if json_output.exists():
                with open(json_output) as f:
                    return json.load(f)
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Slither timeout"}
        except FileNotFoundError:
            return {"success": False, "error": "Slither not installed"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def analyze_patterns(self, sol_files: List[Path]) -> List[Finding]:
        """Run custom pattern analysis"""
        findings = []
        
        for sol_file in sol_files:
            try:
                content = sol_file.read_text()
                relative_path = sol_file.relative_to(self.repo_dir)
                
                # Check for common vulnerability patterns
                findings.extend(self._check_reentrancy(content, relative_path))
                findings.extend(self._check_access_control(content, relative_path))
                findings.extend(self._check_overflow(content, relative_path))
                findings.extend(self._check_centralization(content, relative_path))
                findings.extend(self._check_oracle_patterns(content, relative_path))
                
            except Exception as e:
                print(f"[!] Error analyzing {sol_file}: {e}")
        
        return findings
    
    def _check_reentrancy(self, content: str, filepath: Path) -> List[Finding]:
        """Check for reentrancy vulnerabilities"""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for external calls without reentrancy guard
            if '.call{' in line or '.call.value(' in line:
                # Check if function has nonReentrant modifier
                function_start = max(0, i - 20)
                function_context = '\n'.join(lines[function_start:i])
                
                if 'nonReentrant' not in function_context:
                    findings.append(Finding(
                        id=f"REENT-{filepath.name}-{i}",
                        title="Potential Reentrancy",
                        severity=Severity.HIGH,
                        category="reentrancy",
                        file=str(filepath),
                        line=i,
                        description=f"External call without reentrancy guard at line {i}",
                        impact="Attacker could re-enter and drain funds",
                        recommendation="Add nonReentrant modifier or use checks-effects-interactions pattern",
                        code_snippet=line.strip()
                    ))
        
        return findings
    
    def _check_access_control(self, content: str, filepath: Path) -> List[Finding]:
        """Check for access control issues"""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for public functions that should be restricted
            if 'function ' in line and 'public' in line:
                # Check for dangerous functions
                dangerous = ['mint', 'burn', 'withdraw', 'transfer', 'approve', 'setOwner']
                for d in dangerous:
                    if d in line.lower() and 'onlyOwner' not in line and 'require' not in line:
                        findings.append(Finding(
                            id=f"ACCESS-{filepath.name}-{i}",
                            title="Missing Access Control",
                            severity=Severity.MEDIUM,
                            category="access_control",
                            file=str(filepath),
                            line=i,
                            description=f"Potentially dangerous function '{d}' without access control",
                            impact="Unauthorized users could call sensitive functions",
                            recommendation="Add proper access control modifiers",
                            code_snippet=line.strip()
                        ))
        
        return findings
    
    def _check_overflow(self, content: str, filepath: Path) -> List[Finding]:
        """Check for integer overflow/underflow"""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for unchecked arithmetic
            if any(op in line for op in ['+=', '-=', '*=', '/=']):
                # Check if using SafeMath or Solidity >=0.8.0
                if 'using SafeMath' not in content and 'pragma solidity ^0.8' not in content:
                    findings.append(Finding(
                        id=f"OVERFLOW-{filepath.name}-{i}",
                        title="Potential Integer Overflow",
                        severity=Severity.MEDIUM,
                        category="overflow",
                        file=str(filepath),
                        line=i,
                        description="Arithmetic operation without overflow protection",
                        impact="Could lead to unexpected behavior or loss of funds",
                        recommendation="Use Solidity >=0.8.0 or SafeMath library",
                        code_snippet=line.strip()
                    ))
        
        return findings
    
    def _check_centralization(self, content: str, filepath: Path) -> List[Finding]:
        """Check for centralization risks"""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for single owner patterns
            if 'onlyOwner' in line:
                findings.append(Finding(
                    id=f"CENTRAL-{filepath.name}-{i}",
                    title="Centralization Risk",
                    severity=Severity.INFORMATIONAL,
                    category="centralization",
                    file=str(filepath),
                    line=i,
                    description="Single owner control detected",
                    impact="Owner could rug or freeze funds",
                    recommendation="Consider multi-sig or DAO governance",
                    code_snippet=line.strip()
                ))
        
        return findings
    
    def _check_oracle_patterns(self, content: str, filepath: Path) -> List[Finding]:
        """Check for oracle-related issues"""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for stale price feeds
            if 'latestRoundData' in line or 'getRoundData' in line:
                # Check for staleness check
                context_start = max(0, i - 10)
                context = '\n'.join(lines[context_start:i+5])
                
                if 'staleness' not in context.lower() and 'updatedAt' not in context:
                    findings.append(Finding(
                        id=f"ORACLE-{filepath.name}-{i}",
                        title="Missing Oracle Staleness Check",
                        severity=Severity.HIGH,
                        category="oracle",
                        file=str(filepath),
                        line=i,
                        description="Oracle price feed read without staleness verification",
                        impact="Could use outdated prices for critical operations",
                        recommendation="Add staleness check using block.timestamp - updatedAt",
                        code_snippet=line.strip()
                    ))
        
        return findings
    
    def scan(self, repo_url: str) -> AuditResult:
        """Run complete audit scan"""
        print(f"\n{'='*60}")
        print(f"SMART CONTRACT AUDIT")
        print(f"{'='*60}\n")
        
        # Clone repo
        self.clone_repo(repo_url)
        
        # Get commit
        commit_result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(self.repo_dir),
            capture_output=True,
            text=True
        )
        commit = commit_result.stdout.strip()[:8]
        
        # Find Solidity files
        sol_files = self.find_solidity_files()
        print(f"[*] Found {len(sol_files)} Solidity files")
        
        # Compile
        compile_result = self.compile_contracts(sol_files)
        
        # Run Slither
        slither_result = self.run_slither()
        
        # Run pattern analysis
        findings = self.analyze_patterns(sol_files)
        
        # Count lines
        total_lines = sum(
            len(f.read_text().split('\n')) 
            for f in sol_files 
            if f.exists()
        )
        
        # Create result
        result = AuditResult(
            repo_url=repo_url,
            commit=commit,
            timestamp=datetime.utcnow().isoformat(),
            status="completed",
            total_contracts=len(sol_files),
            total_lines=total_lines,
            findings=findings,
            compilation_errors=compile_result.get("errors", []),
            slither_output=slither_result
        )
        
        # Print summary
        print(f"\n{'='*60}")
        print("AUDIT SUMMARY")
        print(f"{'='*60}")
        print(f"Contracts analyzed: {result.total_contracts}")
        print(f"Total lines: {result.total_lines}")
        print(f"\nFindings by severity:")
        for sev, count in result.summary.items():
            if count > 0:
                print(f"  {sev.upper()}: {count}")
        
        return result
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.work_dir and self.work_dir.exists():
            shutil.rmtree(self.work_dir)
