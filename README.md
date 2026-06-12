# Smart Contract Audit Tool

A powerful automated smart contract security audit platform that clones repos, analyzes Solidity code, detects vulnerabilities, generates reports, and prepares bug bounty submissions.

## Features

- **Automated Analysis** - Clone repos, detect vulnerabilities, generate reports
- **Multi-Tool Integration** - Slither, custom pattern matching, compilation checks
- **POC Generation** - Create proof-of-concept exploits for found vulnerabilities
- **Multiple Report Formats** - JSON, Markdown, HTML
- **Web Dashboard** - Monitor audits in real-time (coming soon)
- **Bug Bounty Ready** - Format reports for submission

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/smart-audit.git
cd smart-audit

# Install dependencies
pip install -r requirements.txt

# Or install as package
pip install -e .
```

### Basic Usage

#### 1. Scan a Repository

```bash
# Using CLI
python cli.py scan https://github.com/owner/repo

# With options
python cli.py scan https://github.com/owner/repo \
  --output ./my-audit \
  --format html \
  --poc
```

#### 2. Start Web Server

```bash
python cli.py serve --port 8000
```

#### 3. Use as Library

```python
from smart_audit.core import AuditEngine
from analyzers.pattern_analyzer import PatternAnalyzer
from generators.report_generator import ReportGenerator

# Initialize
engine = AuditEngine()
analyzer = PatternAnalyzer()

# Clone and analyze
repo_dir = engine.clone_repo("https://github.com/owner/repo")
sol_files = engine.find_solidity_files()

# Run analysis
findings = []
for f in sol_files:
    findings.extend(analyzer.analyze_file(f))

# Generate report
reporter = ReportGenerator("./output")
reporter.generate_json(result)
reporter.generate_markdown(result)
reporter.generate_html(result)
```

## Architecture

```
smart-audit/
├── smart_audit/           # Core package
│   ├── __init__.py
│   ├── core.py           # Main audit engine
│   └── api.py            # FastAPI web interface
├── analyzers/            # Analysis modules
│   ├── slither_analyzer.py
│   ├── pattern_analyzer.py
│   └── compiler_analyzer.py
├── generators/           # Report generators
│   ├── report_generator.py
│   └── poc_generator.py
├── tests/                # Test suite
├── cli.py               # CLI interface
├── demo.py              # Demo script
└── config.yaml          # Configuration
```

## Vulnerability Detection

### Supported Patterns

| Category | Severity | Detection Method |
|----------|----------|------------------|
| Reentrancy | HIGH | External call analysis |
| Integer Overflow | MEDIUM | Arithmetic checks |
| Access Control | MEDIUM | Function visibility |
| tx.origin Usage | HIGH | Authentication patterns |
| Oracle Issues | HIGH | Price feed patterns |
| Centralization | INFO | Owner/admin analysis |
| Floating Pragma | LOW | Version constraints |
| Unchecked Returns | MEDIUM | Call return checks |

### Slither Integration

The tool integrates with Slither for advanced static analysis:

```bash
# Install Slither
pip install slither-analyzer

# Run with Slither
python cli.py scan https://github.com/owner/repo
```

## Output Formats

### JSON Report
```json
{
  "metadata": {
    "repo_url": "...",
    "commit": "...",
    "timestamp": "..."
  },
  "summary": {
    "total_contracts": 10,
    "critical": 2,
    "high": 5,
    "medium": 12
  },
  "findings": [...]
}
```

### Markdown Report
- Executive summary
- Detailed findings by severity
- Code snippets
- Recommendations

### HTML Report
- Interactive dashboard
- Visual severity indicators
- Exportable format

## POC Generation

The tool generates proof-of-concept exploits for found vulnerabilities:

```solidity
// Generated POC for reentrancy
contract ReentrancyPOC {
    TargetContract public target;
    
    receive() external payable {
        if (address(target).balance > 0) {
            target.withdraw();
        }
    }
    
    function attack() external {
        target.deposit{value: 1 ether}();
        target.withdraw();
    }
}
```

## API Endpoints

When running the web server:

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/audit` | Start new audit |
| GET | `/api/audit/{id}` | Get audit status |
| GET | `/api/audit/{id}/report` | Download report |
| GET | `/api/audit/{id}/findings` | Get findings |
| GET | `/api/audits` | List all audits |

## Configuration

Edit `config.yaml` to customize:

```yaml
analysis:
  slither:
    enabled: true
    timeout: 300
  
  pattern_matching:
    enabled: true

output:
  formats: [json, markdown, html]
  include_poc: true
```

## Development

### Run Tests

```bash
pytest tests/ -v
```

### Run Demo

```bash
python demo.py
```

### Add Custom Patterns

Edit `analyzers/pattern_analyzer.py`:

```python
PATTERNS["custom_vuln"] = {
    "patterns": [r'your_regex_pattern'],
    "severity": "HIGH",
    "category": "custom",
    "description": "Your vulnerability description",
    "impact": "Potential impact",
    "recommendation": "How to fix"
}
```

## Roadmap

- [x] Basic vulnerability detection
- [x] Report generation (JSON, MD, HTML)
- [x] POC generation
- [x] Slither integration
- [ ] Web dashboard
- [ ] AI-assisted analysis
- [ ] Multi-chain support
- [ ] Bug bounty platform integration
- [ ] Continuous monitoring

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License

## Disclaimer

This tool is for educational and security research purposes. Always conduct your own due diligence before deploying smart contracts. The tool may not detect all vulnerabilities.
