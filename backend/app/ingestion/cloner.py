"""Non-interactive, non-recursive Git clone for validated public repositories."""

import os
import shutil
import subprocess
from pathlib import Path

from app.ingestion.url_validation import ValidatedRepository

SAFE_PROCESS_VARIABLES = (
    "PATH",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)


def clone_public_repo(
    repository: ValidatedRepository,
    scan_workspace: Path,
    timeout: int,
) -> Path:
    workspace = scan_workspace.resolve(strict=True)
    if not workspace.is_dir():
        raise ValueError("Scan workspace must be a directory")
    if timeout <= 0:
        raise ValueError("Clone timeout must be positive")

    target = workspace / "repo"
    if target.exists():
        raise FileExistsError("Clone target must not already exist")

    hooks = workspace / "disabled-hooks"
    hooks.mkdir(exist_ok=False)
    empty_config = workspace / "empty.gitconfig"
    empty_config.write_text("", encoding="utf-8")

    environment = {
        key: os.environ[key] for key in SAFE_PROCESS_VARIABLES if key in os.environ
    }
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "Never",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(empty_config),
        }
    )

    git_executable = shutil.which("git", path=environment.get("PATH"))
    if git_executable is None:
        raise RuntimeError("Git executable was not found on the allowlisted PATH")

    arguments = [
        git_executable,
        "-c",
        f"core.hooksPath={hooks}",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "http.followRedirects=false",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-recurse-submodules",
    ]
    if repository.requested_ref:
        arguments.extend(["--branch", repository.requested_ref])
    arguments.extend(["--", repository.canonical_url, str(target)])

    subprocess.run(
        arguments,
        shell=False,
        env=environment,
        cwd=workspace,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )
    if not target.is_dir():
        raise RuntimeError("Git reported success without creating the checkout")
    return target

