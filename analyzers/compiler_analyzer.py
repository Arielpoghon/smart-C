"""
Solidity compiler analysis
"""

import json
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class CompilationError:
    file: str
    line: int
    column: int
    severity: str
    message: str
    formatted_message: str


class CompilerAnalyzer:
    """Solidity compiler integration for compilation checks"""
    
    def __init__(self, solc_version: str = "0.8.28"):
        self.solc_version = solc_version
    
    def is_available(self) -> bool:
        """Check if solc is installed"""
        try:
            result = subprocess.run(
                ["solc", "--version"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def compile(self, target_path: Path) -> Dict[str, Any]:
        """Compile Solidity contracts"""
        if not self.is_available():
            return {"success": False, "error": "solc not installed"}
        
        try:
            # Find all sol files
            sol_files = list(target_path.rglob("*.sol"))
            
            if not sol_files:
                return {"success": False, "error": "No Solidity files found"}
            
            # Try to compile
            cmd = ["solc", "--bin", "--abi", "--overwrite"]
            
            # Add all sol files
            for sol_file in sol_files:
                if 'node_modules' not in str(sol_file) and 'lib/' not in str(sol_file):
                    cmd.append(str(sol_file))
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                return {"success": True, "output": result.stdout}
            else:
                errors = self._parse_errors(result.stderr)
                return {
                    "success": False,
                    "errors": errors,
                    "stderr": result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Compilation timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_errors(self, output: str) -> List[CompilationError]:
        """Parse solc error output"""
        errors = []
        
        for line in output.split('\n'):
            if 'Error:' in line or 'Warning:' in line:
                # Simple parsing - could be improved
                errors.append(CompilationError(
                    file="unknown",
                    line=0,
                    column=0,
                    severity="error" if "Error:" in line else "warning",
                    message=line,
                    formatted_message=line
                ))
        
        return errors
    
    def get_version(self) -> str:
        """Get installed solc version"""
        try:
            result = subprocess.run(
                ["solc", "--version"],
                capture_output=True,
                text=True
            )
            for line in result.stdout.split('\n'):
                if 'Version:' in line:
                    return line.split('Version:')[1].strip()
        except Exception:
            pass
        return "unknown"
    
    def get_installable_versions(self) -> List[str]:
        """List available solc versions"""
        try:
            result = subprocess.run(
                ["solc-select", "install", "--list"],
                capture_output=True,
                text=True
            )
            return result.stdout.strip().split('\n')
        except Exception:
            return []
