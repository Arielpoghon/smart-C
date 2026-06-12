#!/usr/bin/env python3
"""
Smart Contract Audit Tool - Enhanced CLI
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from smart_audit.core import AuditEngine, AuditResult, Severity, Finding
from analyzers.pattern_analyzer import PatternAnalyzer
from generators.report_generator import ReportGenerator
from generators.poc_generator import POCGenerator


def scan_command(args):
    """Scan a repository"""
    print(f"\n{'='*60}")
    print("SMART CONTRACT AUDIT TOOL")
    print(f"{'='*60}\n")
    
    # Initialize
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Clone and analyze
    engine = AuditEngine()
    
    try:
        # Clone repo
        print(f"[*] Cloning {args.repo_url}...")
        repo_dir = engine.clone_repo(args.repo_url)
        print(f"[+] Cloned to {repo_dir}")
        
        # Find Solidity files
        sol_files = engine.find_solidity_files()
        print(f"[+] Found {len(sol_files)} Solidity files")
        
        # Run analysis
        print("\n[*] Running analysis...")
        
        # Pattern analysis
        analyzer = PatternAnalyzer()
        all_findings = []
        
        for sol_file in sol_files:
            findings = analyzer.analyze_file(sol_file)
            all_findings.extend(findings)
        
        print(f"[+] Found {len(all_findings)} potential issues")
        
        # Convert to Finding objects
        converted_findings = []
        for f in all_findings:
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
        
        # Get commit hash
        import subprocess
        commit_result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True
        )
        commit = commit_result.stdout.strip()[:8]
        
        # Count lines
        total_lines = sum(
            len(f.read_text().split('\n'))
            for f in sol_files
            if f.exists()
        )
        
        # Create result
        result = AuditResult(
            repo_url=args.repo_url,
            commit=commit,
            timestamp=datetime.utcnow().isoformat(),
            status="completed",
            total_contracts=len(sol_files),
            total_lines=total_lines,
            findings=converted_findings
        )
        
        # Generate reports
        print("\n[*] Generating reports...")
        reporter = ReportGenerator(output_dir)
        
        if args.format in ["json", "all"]:
            json_file = reporter.generate_json(result)
            print(f"  [+] JSON: {json_file}")
        
        if args.format in ["markdown", "all"]:
            md_file = reporter.generate_markdown(result)
            print(f"  [+] Markdown: {md_file}")
        
        if args.format in ["html", "all"]:
            html_file = reporter.generate_html(result)
            print(f"  [+] HTML: {html_file}")
        
        # Generate POCs
        if args.poc:
            print("\n[*] Generating POCs...")
            poc_dir = output_dir / "pocs"
            poc_gen = POCGenerator(poc_dir)
            
            # Get contract name
            contract_name = sol_files[0].stem if sol_files else "Contract"
            
            for finding in converted_findings:
                if finding.severity.value in ['critical', 'high', 'medium']:
                    poc_file = poc_gen.save_poc(finding, contract_name)
                    print(f"  [+] {poc_file.name}")
        
        # Print summary
        print(f"\n{'='*60}")
        print("AUDIT COMPLETE")
        print(f"{'='*60}")
        print(f"Repository: {args.repo_url}")
        print(f"Commit: {commit}")
        print(f"Contracts: {len(sol_files)}")
        print(f"Lines: {total_lines}")
        print(f"\nFindings:")
        for sev, count in result.summary.items():
            if count > 0:
                print(f"  {sev.upper()}: {count}")
        
        print(f"\nReports saved to: {output_dir}")
        
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        engine.cleanup()


def serve_command(args):
    """Start web server"""
    print(f"Starting server on {args.host}:{args.port}...")
    
    try:
        from smart_audit.api import create_app
        import uvicorn
        
        app = create_app()
        uvicorn.run(app, host=args.host, port=args.port)
    except ImportError as e:
        print(f"[!] Missing dependencies: {e}")
        print("    Install with: pip install fastapi uvicorn")
        sys.exit(1)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Smart Contract Audit Tool - Automated security analysis"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a repository")
    scan_parser.add_argument("repo_url", help="GitHub repository URL")
    scan_parser.add_argument("-o", "--output", default="./audit-output", help="Output directory")
    scan_parser.add_argument("--format", choices=["json", "markdown", "html", "all"],
                            default="all", help="Output format")
    scan_parser.add_argument("--poc", action="store_true", help="Generate POCs")
    
    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Start web server")
    serve_parser.add_argument("-p", "--port", type=int, default=8000, help="Port")
    serve_parser.add_argument("-H", "--host", default="0.0.0.0", help="Host")
    
    # Version
    subparsers.add_parser("version", help="Show version")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        scan_command(args)
    elif args.command == "serve":
        serve_command(args)
    elif args.command == "version":
        print("Smart Contract Audit Tool v0.1.0")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
