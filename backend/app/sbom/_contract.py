"""Bridge to the shared ``app.schemas`` contracts owned by Member 1.

When M1's ``app.schemas.inventory`` / ``app.schemas.dependency`` modules are
present they are used directly. Until then this module provides a *private,
temporary* mirror of the README v1.0 examples so the SBOM workstream can be
developed and tested in isolation. This is NOT a competing canonical schema:
delete the fallback branch once M1's bootstrap PR is merged.
"""

from __future__ import annotations

from typing import Literal

try:  # pragma: no cover - exercised only after M1's schemas land
    from app.schemas.dependency import DependencyDocument  # type: ignore[import-not-found]
    from app.schemas.inventory import Inventory  # type: ignore[import-not-found]

    USING_SHARED_SCHEMAS = True
except ImportError:  # pragma: no cover - depends on repository state
    from pydantic import BaseModel, ConfigDict, Field

    USING_SHARED_SCHEMAS = False

    class _Model(BaseModel):
        model_config = ConfigDict(extra="forbid")

    # ---- Inventory (README "Inventory", Member 2 -> Member 3) ----
    class LanguageCount(_Model):
        name: str
        file_count: int

    class FileEntry(_Model):
        path: str
        kind: str
        ecosystem: str

    class Inventory(_Model):  # type: ignore[no-redef]
        schema_version: Literal["1.0"] = "1.0"
        scan_id: str
        languages: list[LanguageCount] = Field(default_factory=list)
        manifests: list[FileEntry] = Field(default_factory=list)
        lockfiles: list[FileEntry] = Field(default_factory=list)
        dockerfiles: list[str] = Field(default_factory=list)
        ci_files: list[str] = Field(default_factory=list)
        iac_files: list[str] = Field(default_factory=list)
        existing_sboms: list[str] = Field(default_factory=list)
        source_directories: list[str] = Field(default_factory=list)
        file_count: int = 0
        partial: bool = False
        warnings: list[str] = Field(default_factory=list)

    # ---- Normalized dependency document (Member 3 -> Member 4) ----
    class Evidence(_Model):
        path: str
        kind: Literal["manifest", "lockfile", "syft-sbom"]
        locator: str

    class Root(_Model):
        root_id: str
        name: str
        path: str
        manifest_path: str
        ecosystem: str

    class Hash(_Model):
        alg: str
        content: str

    class Component(_Model):
        component_id: str
        name: str
        version: str | None
        ecosystem: str
        purl: str | None
        install_path: str | None
        project_path: str
        scope: Literal["runtime", "dev", "optional", "unknown"]
        licenses: list[str]
        hashes: list[Hash]
        evidence: list[Evidence] = Field(min_length=1)
        resolved: bool

    class UnresolvedTarget(_Model):
        name: str
        specifier: str
        ecosystem: str

    class Relationship(_Model):
        relationship_id: str
        from_id: str
        to_id: str | None
        unresolved_target: UnresolvedTarget | None
        resolution_status: Literal["resolved", "unresolved", "ambiguous"]
        type: Literal["DEPENDS_ON"]
        evidence: list[Evidence] = Field(min_length=1)

    class DependencyDocument(_Model):  # type: ignore[no-redef]
        schema_version: Literal["1.0"] = "1.0"
        scan_id: str
        roots: list[Root]
        components: list[Component]
        relationships: list[Relationship]
        partial: bool
        warnings: list[str]


__all__ = ["USING_SHARED_SCHEMAS", "DependencyDocument", "Inventory"]
