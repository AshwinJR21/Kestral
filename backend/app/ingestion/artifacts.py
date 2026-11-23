"""Atomic serialization helpers for validated scan artifacts."""

import json
import os
import uuid
from pathlib import Path

from pydantic import BaseModel


def save_validated_json(path: Path, value: BaseModel) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(value.model_dump(mode="json"), handle, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_validated_json[ModelT: BaseModel](path: Path, model_type: type[ModelT]) -> ModelT:
    with path.open(encoding="utf-8") as handle:
        return model_type.model_validate(json.load(handle))

