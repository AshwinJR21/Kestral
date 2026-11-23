from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_invalid_repository_uses_error_contract() -> None:
    response = client.post(
        "/api/v1/scans",
        json={"repository_url": "file:///etc/passwd", "ref": None},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_REPOSITORY"
    assert response.json()["scan_id"] is None


def test_valid_request_does_not_fake_a_queued_scan() -> None:
    response = client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/example/repository", "ref": "main"},
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "PIPELINE_NOT_READY"


def test_openapi_publishes_all_team_endpoints() -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert {
        "/api/v1/health",
        "/api/v1/scans",
        "/api/v1/scans/{scan_id}",
        "/api/v1/scans/{scan_id}/inventory",
        "/api/v1/scans/{scan_id}/sbom",
        "/api/v1/scans/{scan_id}/graph",
    } <= paths.keys()

