"""
Slither static analysis integration
"""

import json
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class SlitherFinding:
    check: str
    impact: str
    confidence: str
    description: str
    contract: str
    function: str
    file: str
    line: int
    severity: str


class SlitherAnalyzer:
    """Wrapper around Slither static analysis tool"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 300)
        
    def is_available(self) -> bool:
        """Check if Slither is installed"""
        try:
            result = subprocess.run(
                ["slither", "--version"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def analyze(self, target_path: Path) -> Dict[str, Any]:
        """Run Slither analysis on a target"""
        if not self.is_available():
            return {"success": False, "error": "Slither not installed"}
        
        output_file = target_path / "slither-results.json"
        
        try:
            # Run Slither with JSON output
            cmd = [
                "slither",
                str(target_path),
                "--json", str(output_file),
                "--checklist",
                "--markdown-root", str(target_path),
                "--json-versions"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # Parse JSON output
            if output_file.exists():
                with open(output_file) as f:
                    data = json.load(f)
                return self._parse_results(data)
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Analysis timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_results(self, data: Dict) -> Dict[str, Any]:
        """Parse Slither JSON output"""
        findings = []
        
        for detector in data.get("results", {}).get("detectors", []):
            finding = SlitherFinding(
                check=detector.get("check", ""),
                impact=detector.get("impact", ""),
                confidence=detector.get("confidence", ""),
                description=detector.get("description", ""),
                contract=detector.get("contract", ""),
                function=detector.get("function", ""),
                file=detector.get("source", {}).get("filename", ""),
                line=detector.get("source", {}).get("line", 0),
                severity=detector.get("impact", "Unknown")
            )
            findings.append(finding)
        
        return {
            "success": True,
            "findings": findings,
            "summary": {
                "total": len(findings),
                "high": sum(1 for f in findings if f.severity == "High"),
                "medium": sum(1 for f in findings if f.severity == "Medium"),
                "low": sum(1 for f in findings if f.severity == "Low"),
                "informational": sum(1 for f in findings if f.severity == "Informational")
            }
        }
    
    def get_detectors(self) -> List[str]:
        """List available Slither detectors"""
        try:
            result = subprocess.run(
                ["slither", "--list-detectors"],
                capture_output=True,
                text=True
            )
            return result.stdout.strip().split('\n')
        except Exception:
            return []
