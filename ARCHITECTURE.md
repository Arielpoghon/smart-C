# Smart Contract Audit Tool - Architecture & Workflow

## Overview
An automated smart contract security audit platform that clones repos, analyzes Solidity code, detects vulnerabilities, generates reports, and prepares bug bounty submissions.

---

## Core Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    INPUT: GitHub Repo URL                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: REPO CLONING & PARSING                               │
│  ├─ Clone repository (git clone)                                │
│  ├─ Detect Solidity files (*.sol)                               │
│  ├─ Parse contract structure (inheritance, imports)             │
│  ├─ Extract ABI and function signatures                         │
│  └─ Identify external dependencies (OpenZeppelin, etc.)         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 2: STATIC ANALYSIS                                      │
│  ├─ Slither (Trail of Bits) - vulnerability detection           │
│  ├─ Solc compilation check                                      │
│  ├─ Custom AST analysis                                         │
│  └─ Pattern matching for known vulnerabilities                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 3: DYNAMIC ANALYSIS (Optional)                          │
│  ├─ Mythril symbolic execution                                  │
│  ├─ Echidna fuzzing (if configured)                             │
│  └─ Foundry invariant tests                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 4: VULNERABILITY CLASSIFICATION                         │
│  ├─ Reentrancy                                                 │
│  ├─ Integer overflow/underflow                                  │
│  ├─ Access control issues                                      │
│  ├─ Oracle manipulation                                        │
│  ├─ Flash loan attacks                                         │
│  ├─ Front-running vulnerabilities                              │
│  ├─ Logic errors                                               │
│  ├─ Gas optimization                                           │
│  └─ Centralization risks                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 5: REPORT GENERATION                                    │
│  ├─ Severity classification (Critical/High/Medium/Low/Info)    │
│  ├─ Detailed finding descriptions                              │
│  ├─ Code location (file:line)                                   │
│  ├─ Recommended fixes                                          │
│  └─ Executive summary                                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 6: POC GENERATION                                       │
│  ├─ Generate proof-of-concept exploits                         │
│  ├─ Create Foundry/Hardhat test files                          │
│  └─ Ready for bug bounty submission                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  OUTPUT: Audit Report + POCs + Bug Bounty Submission           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

### Backend (Python FastAPI)
- **FastAPI** - REST API framework
- **GitPython** - Repository cloning
- **solcx** - Solidity compilation
- **web3.py** - Ethereum interaction
- **Jinja2** - Report templating

### Analysis Engine
- **Slither** - Static analysis (primary)
- **Mythril** - Symbolic execution (optional)
- **solc** - Compiler checks
- **Custom AST parser** - Pattern detection

### Database
- **SQLite** - Local storage (simple)
- **PostgreSQL** - Production (scalable)

### Frontend (Optional)
- **Streamlit** - Quick dashboard
- **React** - Full web UI

---

## Vulnerability Detection Matrix

| Category | Tool | Detection Method |
|----------|------|------------------|
| Reentrancy | Slither | Call graph analysis |
| Integer Overflow | Slither + Custom | Arithmetic checks |
| Access Control | Custom | Role-based analysis |
| Oracle Issues | Custom | Price feed patterns |
| Flash Loan | Custom | Temporal analysis |
| Front-running | Custom | MEV patterns |
| Gas Optimization | Slither | Gas reporters |
| Logic Errors | Manual + AI | Code review |
| Centralization | Custom | Admin role analysis |

---

## Output Format

### JSON Report Structure
```json
{
  "repo": "owner/repo",
  "commit": "abc123",
  "timestamp": "2026-06-12T00:00:00Z",
  "summary": {
    "total_contracts": 10,
    "total_lines": 2500,
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 8,
    "informational": 15
  },
  "findings": [
    {
      "id": "VULN-001",
      "title": "Reentrancy in withdraw()",
      "severity": "HIGH",
      "category": "reentrancy",
      "file": "contracts/Vault.sol",
      "line": 142,
      "description": "...",
      "impact": "...",
      "recommendation": "...",
      "poc": "..."
    }
  ]
}
```

---

## API Endpoints

```
POST   /api/audit              - Start new audit
GET    /api/audit/{id}         - Get audit status
GET    /api/audit/{id}/report  - Download report
POST   /api/audit/{id}/poc     - Generate POC
GET    /api/audits             - List all audits
DELETE /api/audit/{id}         - Delete audit
```

---

## Configuration

```yaml
tools:
  slither:
    enabled: true
    config: .slither.config.json
  mythril:
    enabled: false
    timeout: 300
  echidna:
    enabled: false

analysis:
  custom_patterns: true
  ai_assisted: false
  max_file_size: 100000  # bytes

output:
  format: [json, markdown, html]
  include_poc: true
  include_tests: true
```

---

## Security Considerations

1. **Sandboxed Execution** - Clone repos in isolated containers
2. **No Secret Exposure** - Never log private keys, secrets
3. **Rate Limiting** - Prevent abuse
4. **Input Validation** - Sanitize repo URLs
5. **Timeout Protection** - Kill long-running analyses

---

## Development Phases

### Phase 1: MVP (Week 1-2)
- [ ] Basic repo cloning
- [ ] Slither integration
- [ ] JSON report generation
- [ ] CLI interface

### Phase 2: Core Features (Week 3-4)
- [ ] Web API (FastAPI)
- [ ] Custom vulnerability patterns
- [ ] POC generation
- [ ] HTML reports

### Phase 3: Advanced (Week 5-8)
- [ ] AI-assisted analysis
- [ ] Bug bounty integration
- [ ] Dashboard UI
- [ ] Continuous monitoring

### Phase 4: Scale (Week 9+)
- [ ] Multi-chain support
- [ ] Team collaboration
- [ ] API marketplace
- [ ] Commercial features
