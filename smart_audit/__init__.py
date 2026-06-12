"""
Smart Contract Audit Tool
Automated security analysis for Solidity smart contracts
"""

__version__ = "0.1.0"
__author__ = "Security Audit Tool"

from .core import AuditEngine, AuditResult, Severity, Finding

__all__ = [
    "AuditEngine",
    "AuditResult",
    "Severity",
    "Finding",
]
