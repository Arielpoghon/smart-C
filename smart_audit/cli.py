"""
Command-line interface for Smart Contract Audit Tool
"""

import sys
import argparse
from pathlib import Path
from typing import List, Optional

from .core import AuditEngine, AuditResult
from .generators import ReportGenerator, POCGenerator


def main(args: Optional[List[str]] = None):
    """Main CLI entry point"""
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
    scan_parser.add_argument("--no-slither", action="store_true", help="Skip Slither analysis")
    scan_parser.add_argument("--poc", action="store_true", help="Generate POCs")
    
    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Start web server")
    serve_parser.add_argument("-p", "--port", type=int, default=8000, help="Port number")
    serve_parser.add_argument("-H", "--host", default="0.0.0.0", help="Host address")
    
    # Version command
    subparsers.add_parser("version", help="Show version")
    
    parsed = parser.parse_args(args)
    
    if parsed.command == "scan":
        run_scan(parsed)
    elif parsed.command == "serve":
        run_server(parsed)
    elif parsed.command == "version":
        print("Smart Contract Audit Tool v0.1.0")
    else:
        parser.print_help()


def run_scan(args):
    """Run the scan command"""
    print(f"\n{'='*60}")
    print("SMART CONTRACT AUDIT TOOL")
    print(f"{'='*60}\n")
    
    # Initialize engine
    engine = AuditEngine()
    
    try:
        # Run audit
        result = engine.scan(args.repo_url)
        
        # Generate reports
        output_dir = Path(args.output)
        reporter = ReportGenerator(output_dir)
        
        print(f"\n[*] Generating reports in {output_dir}...")
        
        if args.format in ["json", "all"]:
            json_file = reporter.generate_json(result)
            print(f"  [+] JSON report: {json_file}")
        
        if args.format in ["markdown", "all"]:
            md_file = reporter.generate_markdown(result)
            print(f"  [+] Markdown report: {md_file}")
        
        if args.format in ["html", "all"]:
            html_file = reporter.generate_html(result)
            print(f"  [+] HTML report: {html_file}")
        
        # Generate POCs if requested
        if args.poc:
            print("\n[*] Generating Proof of Concepts...")
            poc_dir = output_dir / "pocs"
            poc_generator = POCGenerator(poc_dir)
            
            # Get contract name from first file
            sol_files = engine.find_solidity_files()
            contract_name = sol_files[0].stem if sol_files else "Contract"
            
            poc_files = poc_generator.generate_all_pocs(result.findings, contract_name)
            print(f"  [+] Generated {len(poc_files)} POC files")
        
        # Print summary
        print(f"\n{'='*60}")
        print("SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"Repository: {args.repo_url}")
        print(f"Commit: {result.commit}")
        print(f"Contracts: {result.total_contracts}")
        print(f"Lines of code: {result.total_lines}")
        print(f"\nFindings:")
        for sev, count in result.summary.items():
            if count > 0:
                print(f"  {sev.upper()}: {count}")
        
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
    finally:
        engine.cleanup()


def run_server(args):
    """Start the web server"""
    print(f"Starting web server on {args.host}:{args.port}...")
    
    try:
        from .api import create_app
        app = create_app()
        import uvicorn
        uvicorn.run(app, host=args.host, port=args.port)
    except ImportError:
        print("[!] Web server dependencies not installed.")
        print("    Install with: pip install fastapi uvicorn")
        sys.exit(1)


if __name__ == "__main__":
    main()
