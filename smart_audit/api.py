"""
FastAPI web interface
"""

from pathlib import Path
from typing import Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from ..core import AuditEngine, AuditResult


app = FastAPI(
    title="Smart Contract Audit API",
    description="Automated smart contract security analysis",
    version="0.1.0"
)

# Store for audit results
audits = {}


class AuditRequest(BaseModel):
    repo_url: str
    output_format: str = "all"
    generate_poc: bool = False


class AuditResponse(BaseModel):
    id: str
    status: str
    repo_url: str
    started_at: str


class FindingResponse(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    file: str
    line: int
    description: str
    impact: str
    recommendation: str


@app.get("/")
async def root():
    return {
        "name": "Smart Contract Audit API",
        "version": "0.1.0",
        "docs": "/docs"
    }


@app.post("/api/audit", response_model=AuditResponse)
async def start_audit(request: AuditRequest, background_tasks: BackgroundTasks):
    """Start a new audit"""
    import uuid
    
    audit_id = str(uuid.uuid4())[:8]
    
    # Store initial state
    audits[audit_id] = {
        "id": audit_id,
        "status": "running",
        "repo_url": request.repo_url,
        "started_at": datetime.utcnow().isoformat(),
        "result": None
    }
    
    # Run audit in background
    background_tasks.add_task(run_audit_task, audit_id, request)
    
    return AuditResponse(
        id=audit_id,
        status="running",
        repo_url=request.repo_url,
        started_at=audits[audit_id]["started_at"]
    )


@app.get("/api/audit/{audit_id}")
async def get_audit_status(audit_id: str):
    """Get audit status"""
    if audit_id not in audits:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    audit = audits[audit_id]
    
    response = {
        "id": audit["id"],
        "status": audit["status"],
        "repo_url": audit["repo_url"],
        "started_at": audit["started_at"]
    }
    
    if audit["result"]:
        response["summary"] = audit["result"].summary
        response["total_contracts"] = audit["result"].total_contracts
        response["total_lines"] = audit["result"].total_lines
    
    return response


@app.get("/api/audit/{audit_id}/report")
async def get_audit_report(audit_id: str, format: str = "json"):
    """Get audit report"""
    if audit_id not in audits:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    audit = audits[audit_id]
    
    if audit["status"] != "completed":
        raise HTTPException(status_code=400, detail="Audit not completed")
    
    # Generate report
    output_dir = Path(f"./audit-output/{audit_id}")
    reporter = ReportGenerator(output_dir)
    
    if format == "json":
        file_path = reporter.generate_json(audit["result"])
    elif format == "markdown":
        file_path = reporter.generate_markdown(audit["result"])
    elif format == "html":
        file_path = reporter.generate_html(audit["result"])
    else:
        raise HTTPException(status_code=400, detail="Invalid format")
    
    return FileResponse(
        path=file_path,
        filename=f"audit-report.{format if format != 'markdown' else 'md'}",
        media_type="application/octet-stream"
    )


@app.get("/api/audit/{audit_id}/findings")
async def get_audit_findings(
    audit_id: str,
    severity: Optional[str] = None,
    category: Optional[str] = None
):
    """Get audit findings with optional filters"""
    if audit_id not in audits:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    audit = audits[audit_id]
    
    if audit["status"] != "completed":
        raise HTTPException(status_code=400, detail="Audit not completed")
    
    findings = audit["result"].findings
    
    # Apply filters
    if severity:
        findings = [f for f in findings if f.severity.value == severity]
    
    if category:
        findings = [f for f in findings if f.category == category]
    
    return [
        FindingResponse(
            id=f.id,
            title=f.title,
            severity=f.severity.value,
            category=f.category,
            file=f.file,
            line=f.line,
            description=f.description,
            impact=f.impact,
            recommendation=f.recommendation
        )
        for f in findings
    ]


@app.get("/api/audits")
async def list_audits():
    """List all audits"""
    return [
        {
            "id": audit["id"],
            "status": audit["status"],
            "repo_url": audit["repo_url"],
            "started_at": audit["started_at"]
        }
        for audit in audits.values()
    ]


@app.delete("/api/audit/{audit_id}")
async def delete_audit(audit_id: str):
    """Delete an audit"""
    if audit_id not in audits:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    del audits[audit_id]
    return {"message": "Audit deleted"}


def run_audit_task(audit_id: str, request: AuditRequest):
    """Background task to run audit"""
    try:
        engine = AuditEngine()
        result = engine.scan(request.repo_url)
        
        audits[audit_id]["status"] = "completed"
        audits[audit_id]["result"] = result
        
    except Exception as e:
        audits[audit_id]["status"] = "failed"
        audits[audit_id]["error"] = str(e)
    
    finally:
        engine.cleanup()


def create_app():
    """Create and return the FastAPI app"""
    return app
