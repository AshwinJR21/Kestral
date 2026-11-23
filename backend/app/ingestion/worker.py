"""Integration entry point reserved for the fixture-backed M1 orchestration PR."""

from app.ingestion.interfaces import PipelineComponentUnavailable


def run_scan(scan_id: str) -> None:
    """Fail explicitly until DB transitions and M2-M4 implementations are integrated."""

    raise PipelineComponentUnavailable(
        f"Scan orchestration is not integrated for {scan_id}; the bootstrap exposes contracts only"
    )

