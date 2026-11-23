"""Scan contract endpoints for the bootstrap milestone.

The endpoint signatures are intentionally live in OpenAPI while orchestration remains unavailable
until M2-M4 implementations are integrated. Returning a structured 503 prevents a stub from
claiming that a scan was queued when no durable scan row or worker exists yet.
"""

from fastapi import APIRouter

from app.api.errors import ApiProblem
from app.ingestion.url_validation import validate_repo_url
from app.schemas.dependency import DependencyDocument
from app.schemas.error import ErrorResponse
from app.schemas.graph import GraphDocument
from app.schemas.inventory import Inventory
from app.schemas.scan import ScanCreate, ScanCreated, ScanState

router = APIRouter(tags=["scans"])

ERROR_RESPONSES = {
    404: {"model": ErrorResponse, "description": "Unknown scan ID"},
    409: {"model": ErrorResponse, "description": "Artifact is not ready"},
    422: {"model": ErrorResponse, "description": "Invalid repository URL or ref"},
    429: {"model": ErrorResponse, "description": "Scanner concurrency limit reached"},
    503: {"model": ErrorResponse, "description": "Scanner service is temporarily unavailable"},
}


def _bootstrap_unavailable(scan_id: str | None = None) -> ApiProblem:
    return ApiProblem(
        status=503,
        code="PIPELINE_NOT_READY",
        message="The API contract is available, but scan orchestration is not integrated yet",
        scan_id=scan_id,
    )


@router.post(
    "/scans",
    response_model=ScanCreated,
    status_code=202,
    responses=ERROR_RESPONSES,
)
def create_scan(body: ScanCreate) -> ScanCreated:
    try:
        validate_repo_url(body.repository_url, body.ref)
    except ValueError as exc:
        raise ApiProblem(
            status=422,
            code="INVALID_REPOSITORY",
            message=str(exc),
        ) from None
    raise _bootstrap_unavailable()


@router.get("/scans/{scan_id}", response_model=ScanState, responses=ERROR_RESPONSES)
def get_scan(scan_id: str) -> ScanState:
    raise _bootstrap_unavailable(scan_id)


@router.get(
    "/scans/{scan_id}/inventory",
    response_model=Inventory,
    responses=ERROR_RESPONSES,
)
def get_inventory(scan_id: str) -> Inventory:
    raise _bootstrap_unavailable(scan_id)


@router.get(
    "/scans/{scan_id}/sbom",
    response_model=DependencyDocument,
    responses=ERROR_RESPONSES,
)
def get_sbom(scan_id: str) -> DependencyDocument:
    raise _bootstrap_unavailable(scan_id)


@router.get(
    "/scans/{scan_id}/graph",
    response_model=GraphDocument,
    responses=ERROR_RESPONSES,
)
def get_graph(scan_id: str) -> GraphDocument:
    raise _bootstrap_unavailable(scan_id)

