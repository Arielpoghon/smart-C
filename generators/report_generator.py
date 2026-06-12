"""
Report generation in multiple formats
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from string import Template


class ReportGenerator:
    """Generate audit reports in various formats"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_json(self, audit_result: Any, filename: str = "audit-report.json") -> Path:
        """Generate JSON report"""
        output_file = self.output_dir / filename
        
        report = {
            "metadata": {
                "repo_url": audit_result.repo_url,
                "commit": audit_result.commit,
                "timestamp": audit_result.timestamp,
                "status": audit_result.status
            },
            "summary": {
                "total_contracts": audit_result.total_contracts,
                "total_lines": audit_result.total_lines,
                "findings": audit_result.summary
            },
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "category": f.category,
                    "file": f.file,
                    "line": f.line,
                    "description": f.description,
                    "impact": f.impact,
                    "recommendation": f.recommendation,
                    "code_snippet": f.code_snippet,
                    "poc": f.poc
                }
                for f in audit_result.findings
            ],
            "compilation": {
                "errors": audit_result.compilation_errors
            },
            "slither": audit_result.slither_output
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return output_file
    
    def generate_markdown(self, audit_result: Any, filename: str = "audit-report.md") -> Path:
        """Generate Markdown report"""
        output_file = self.output_dir / filename
        
        md_content = self._build_markdown(audit_result)
        
        with open(output_file, 'w') as f:
            f.write(md_content)
        
        return output_file
    
    def _build_markdown(self, audit_result: Any) -> str:
        """Build Markdown report content"""
        summary = audit_result.summary
        
        md = f"""# Smart Contract Audit Report

## Metadata
- **Repository**: {audit_result.repo_url}
- **Commit**: {audit_result.commit}
- **Date**: {audit_result.timestamp}
- **Status**: {audit_result.status}

## Executive Summary

| Metric | Value |
|--------|-------|
| Contracts Analyzed | {audit_result.total_contracts} |
| Total Lines of Code | {audit_result.total_lines} |
| Critical Findings | {summary.get('critical', 0)} |
| High Findings | {summary.get('high', 0)} |
| Medium Findings | {summary.get('medium', 0)} |
| Low Findings | {summary.get('low', 0)} |
| Informational | {summary.get('informational', 0)} |

## Findings

"""
        
        # Group findings by severity
        severity_order = ['critical', 'high', 'medium', 'low', 'informational']
        
        for severity in severity_order:
            findings = [f for f in audit_result.findings if f.severity.value == severity]
            if findings:
                md += f"### {severity.upper()} Severity\n\n"
                
                for finding in findings:
                    md += f"""#### {finding.title}

- **ID**: {finding.id}
- **Category**: {finding.category}
- **File**: `{finding.file}:{finding.line}`
- **Severity**: {finding.severity.value.upper()}

**Description**: {finding.description}

**Impact**: {finding.impact}

**Recommendation**: {finding.recommendation}

"""
                    
                    if finding.code_snippet:
                        md += f"**Code Snippet**:\n```solidity\n{finding.code_snippet}\n```\n\n"
                    
                    if finding.poc:
                        md += f"**Proof of Concept**:\n```solidity\n{finding.poc}\n```\n\n"
                    
                    md += "---\n\n"
        
        # Add recommendations
        md += """## Recommendations

1. **Immediate Actions**
   - Fix all Critical and High severity issues before deployment
   - Review Medium severity issues and implement fixes
   - Consider Low severity issues for best practices

2. **Testing**
   - Add comprehensive unit tests
   - Implement integration tests
   - Consider formal verification for critical paths

3. **Deployment**
   - Use a well-tested deployment framework
   - Implement proper access control
   - Set up monitoring and alerting

## Disclaimer

This audit report is based on the codebase at the time of analysis. Security is an ongoing process, and new vulnerabilities may be discovered over time. Always conduct your own due diligence before deploying smart contracts.

---
*Generated by Smart Contract Audit Tool*
"""
        
        return md
    
    def generate_html(self, audit_result: Any, filename: str = "audit-report.html") -> Path:
        """Generate HTML report"""
        output_file = self.output_dir / filename
        
        html_content = self._build_html(audit_result)
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        return output_file
    
    def _build_html(self, audit_result: Any) -> str:
        """Build HTML report content"""
        summary = audit_result.summary
        
        findings_html = ""
        for finding in audit_result.findings:
            color = {
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#28a745',
                'informational': '#17a2b8'
            }.get(finding.severity.value, '#6c757d')
            
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; padding: 10px; margin: 10px 0;">
                <h3>{finding.title}</h3>
                <p><strong>ID:</strong> {finding.id} | <strong>Severity:</strong> <span style="color: {color};">{finding.severity.value.upper()}</span></p>
                <p><strong>File:</strong> {finding.file}:{finding.line}</p>
                <p><strong>Description:</strong> {finding.description}</p>
                <p><strong>Impact:</strong> {finding.impact}</p>
                <p><strong>Recommendation:</strong> {finding.recommendation}</p>
                {"<pre><code>" + finding.code_snippet + "</code></pre>" if finding.code_snippet else ""}
            </div>
            """
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Contract Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 20px 0; }}
        .summary-card {{ background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }}
        .finding {{ background: #fff; padding: 15px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        pre {{ background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>Smart Contract Audit Report</h1>
    
    <h2>Metadata</h2>
    <table>
        <tr><td>Repository</td><td>{audit_result.repo_url}</td></tr>
        <tr><td>Commit</td><td>{audit_result.commit}</td></tr>
        <tr><td>Date</td><td>{audit_result.timestamp}</td></tr>
    </table>
    
    <h2>Summary</h2>
    <div class="summary">
        <div class="summary-card">
            <h3>{audit_result.total_contracts}</h3>
            <p>Contracts</p>
        </div>
        <div class="summary-card">
            <h3>{audit_result.total_lines}</h3>
            <p>Lines of Code</p>
        </div>
        <div class="summary-card" style="color: #dc3545;">
            <h3>{summary.get('critical', 0)}</h3>
            <p>Critical</p>
        </div>
        <div class="summary-card" style="color: #fd7e14;">
            <h3>{summary.get('high', 0)}</h3>
            <p>High</p>
        </div>
        <div class="summary-card" style="color: #ffc107;">
            <h3>{summary.get('medium', 0)}</h3>
            <p>Medium</p>
        </div>
        <div class="summary-card" style="color: #28a745;">
            <h3>{summary.get('low', 0)}</h3>
            <p>Low</p>
        </div>
    </div>
    
    <h2>Findings ({len(audit_result.findings)})</h2>
    {findings_html}
    
    <hr>
    <p><em>Generated by Smart Contract Audit Tool</em></p>
</body>
</html>
"""
        
        return html
