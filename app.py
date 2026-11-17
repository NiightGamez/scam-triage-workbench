"""FastAPI Application for Scam & Phishing Infrastructure Triage Workbench."""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import List

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from api.limiter import rate_limiter
from api.samples import get_sample_report, get_sample_summaries
from triage import __version__
from triage.defang import refang_string
from triage.engine import TriageEngine
from triage.models import TriageReport
from triage.network import SSRFProtectionError
from triage.reporter import to_markdown

# Environment flags (defaults to true if running in Docker/prod environment)
DEMO_MODE_ONLY = os.getenv("DEMO_MODE_ONLY", "false").lower() in ("true", "1", "yes")

app = FastAPI(
    title="Scam & Phishing Infrastructure Triage Workbench",
    description="Passive OSINT infrastructure enrichment and heuristic risk scoring.",
    version=__version__,
)

# 1. Strict HTTP Security Response Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Enforce defense-in-depth HTTP security response headers."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    return response


# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Engine instance
engine = TriageEngine()

STATIC_DIR = Path(__file__).parent / "static"


# 2. Strict Input Validation Model
class TriageRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048, description="Suspicious URL, domain, or IP address")

    @field_validator("target")
    @classmethod
    def validate_target_security(cls, value: str) -> str:
        if not value:
            raise ValueError("Target cannot be empty.")

        # Reject control characters (ASCII < 32 or 127) anywhere in the input
        for char in value:
            if ord(char) < 32 or ord(char) == 127:
                raise ValueError("Target contains illegal control characters.")

        clean = value.strip()
        if not clean:
            raise ValueError("Target cannot be empty.")

        refanged = refang_string(clean)

        # Enforce scheme restrictions and length limits
        has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", refanged))
        if has_scheme:
            if len(clean) > 2048:
                raise ValueError("URL target exceeds maximum length of 2048 characters.")
            scheme = refanged.split("://")[0].lower()
            if scheme not in ("http", "https"):
                raise ValueError(f"Unsupported URI scheme '{scheme}'. Only HTTP and HTTPS are permitted.")
        else:
            if len(clean) > 253:
                raise ValueError("Domain or IP target exceeds maximum length of 253 characters.")
            # Check for non-standard schemes masquerading without // (e.g. javascript:, file:, data:)
            m = re.match(r"^([a-zA-Z0-9+\-.]+):", clean)
            if m:
                prefix = m.group(1).lower()
                if prefix in ("javascript", "data", "file", "ftp", "gopher", "ldap", "dict", "tftp", "telnet"):
                    raise ValueError(f"Dangerous or unsupported scheme '{prefix}:' is strictly forbidden.")

        return clean


def get_client_ip(request: Request) -> str:
    """Extract client IP from reverse proxy headers or direct socket connection."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


@app.get("/", include_in_schema=False)
async def serve_index():
    """Serve the single-page dark-mode web application."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "Scam Triage Workbench API is running. UI not found in static/."}


@app.get("/api/health")
async def health():
    """Healthcheck and operational status endpoint."""
    return {
        "status": "ok",
        "version": __version__,
        "demo_mode": DEMO_MODE_ONLY,
    }


@app.get("/api/samples")
async def list_samples():
    """List metadata for pre-loaded demonstration sample cases."""
    return get_sample_summaries()


@app.get("/api/samples/{sample_id}", response_model=TriageReport)
async def get_sample(sample_id: str):
    """Retrieve full structured report for a pre-loaded sample case."""
    report = get_sample_report(sample_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Sample case '{sample_id}' not found")
    return report


@app.post("/api/triage", response_model=TriageReport)
async def run_triage(req: TriageRequest, request: Request):
    """Execute passive infrastructure triage against a suspicious target."""
    client_ip = get_client_ip(request)

    # 1. Demo Mode Check
    if DEMO_MODE_ONLY:
        raise HTTPException(
            status_code=403,
            detail=(
                "Live scanning is disabled in Demo Mode to protect public instances. "
                "You can freely inspect all sample reports or run the workbench locally via Docker."
            ),
        )

    # 2. In-Memory Rate Limiting
    is_limited, retry_after = rate_limiter.is_rate_limited(client_ip)
    if is_limited:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded (maximum 10 requests per minute). Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

    # 3. Execute Triage Pipeline with SSRF Handling
    try:
        report = engine.triage(req.target)
        return report
    except SSRFProtectionError as e:
        raise HTTPException(
            status_code=400,
            detail=f"SSRF Guardrail Violation: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Triage execution failed: {str(e)}",
        )


@app.post("/api/export/markdown")
async def export_markdown(report: TriageReport):
    """Generate and return a downloadable Markdown triage brief."""
    md_content = to_markdown(report)
    safe_filename = f"triage_{report.target.host.replace('.', '_')}.md"
    return Response(
        content=md_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'},
    )


# Mount static assets directory
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
