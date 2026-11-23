import subprocess
from pathlib import Path

from app.ingestion.cloner import clone_public_repo
from app.ingestion.url_validation import ValidatedRepository


def test_clone_uses_hardened_noninteractive_arguments(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["arguments"] = arguments
        captured.update(kwargs)
        Path(arguments[-1]).mkdir()
        return subprocess.CompletedProcess(arguments, 0, "", "")

    monkeypatch.setattr("app.ingestion.cloner.shutil.which", lambda *_args, **_kwargs: "git")
    monkeypatch.setattr("app.ingestion.cloner.subprocess.run", fake_run)
    repository = ValidatedRepository(
        owner="example",
        name="repository",
        canonical_url="https://github.com/example/repository",
        requested_ref="main",
    )

    checkout = clone_public_repo(repository, tmp_path, timeout=30)
    arguments = captured["arguments"]

    assert checkout == tmp_path / "repo"
    assert isinstance(arguments, list)
    assert "--no-recurse-submodules" in arguments
    assert "http.followRedirects=false" in arguments
    assert arguments[-3:] == ["--", repository.canonical_url, str(checkout)]
    assert captured["shell"] is False
    assert captured["timeout"] == 30
    environment = captured["env"]
    assert isinstance(environment, dict)
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert "GITHUB_TOKEN" not in environment
    assert "SSH_AUTH_SOCK" not in environment

