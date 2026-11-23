"""Safe per-scan workspace allocation."""

import re
from dataclasses import dataclass
from pathlib import Path

SCAN_ID = re.compile(r"^scan_[0-9a-f]{32}$")


@dataclass(frozen=True)
class ScanDirectories:
    workspace: Path
    output: Path


def _child(root: Path, scan_id: str) -> Path:
    candidate = (root / scan_id).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError("Scan directory escaped its configured root") from exc
    return candidate


def allocate_scan_dirs(
    scan_id: str, workspace_root: Path, scan_output_root: Path
) -> ScanDirectories:
    if not SCAN_ID.fullmatch(scan_id):
        raise ValueError("Invalid scan ID")
    workspace_root.mkdir(parents=True, exist_ok=True)
    scan_output_root.mkdir(parents=True, exist_ok=True)
    workspace = _child(workspace_root, scan_id)
    output = _child(scan_output_root, scan_id)
    workspace.mkdir(exist_ok=False)
    try:
        output.mkdir(exist_ok=False)
    except Exception:
        workspace.rmdir()
        raise
    return ScanDirectories(workspace=workspace, output=output)

