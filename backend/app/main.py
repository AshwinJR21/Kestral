"""FastAPI application entry point."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.errors import register_exception_handlers
from app.api.routes.scans import router as scans_router
from app.config import settings

app = FastAPI(
    title="Software Supply Chain Guardian",
    version="0.1.0",
    description="Phase 1 dependency inventory and graph API",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
register_exception_handlers(app)
app.include_router(scans_router, prefix="/api/v1")


@app.get("/api/v1/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok"}

