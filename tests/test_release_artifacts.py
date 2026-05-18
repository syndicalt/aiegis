from pathlib import Path

import yaml


def test_release_check_script_runs_required_quality_gates() -> None:
    script = Path("scripts/release-check.sh").read_text(encoding="utf-8")

    assert "pytest --cov=aiegis --cov-report=term-missing --cov-fail-under=90" in script
    assert "ruff check ." in script
    assert "mypy src" in script
    assert "python -m build" in script
    assert "twine check dist/*" in script


def test_ci_workflow_runs_release_check_on_supported_python_versions() -> None:
    workflow = yaml.safe_load(Path(".github/workflows/ci.yml").read_text(encoding="utf-8"))

    assert workflow["name"] == "CI"
    assert workflow["on"] == ["push", "pull_request"]
    test_job = workflow["jobs"]["test"]
    assert test_job["strategy"]["matrix"]["python-version"] == ["3.11", "3.12", "3.13"]
    steps = test_job["steps"]
    assert any(step.get("uses") == "actions/checkout@v4" for step in steps)
    assert any(step.get("uses") == "actions/setup-python@v5" for step in steps)
    assert any(step.get("run") == "scripts/release-check.sh" for step in steps)


def test_production_readiness_plan_tracks_ci_slice() -> None:
    plan = Path("docs/production-readiness.md").read_text(encoding="utf-8")

    assert "- [x] CI quality gate" in plan
    assert "- [x] Container runtime" in plan
    assert "- [ ] Red-team regression corpus" in plan


def test_dockerfile_runs_as_non_root_mcp_runtime() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

    assert "FROM python:3.13-slim" in dockerfile
    assert "useradd" in dockerfile
    assert "USER aiegis" in dockerfile
    assert "VOLUME [\"/var/lib/aiegis\"]" in dockerfile
    assert 'ENTRYPOINT ["aiegis"]' in dockerfile
    assert 'CMD ["mcp-stdio"]' in dockerfile


def test_compose_example_mounts_audit_and_policy_data() -> None:
    compose = yaml.safe_load(Path("deploy/docker-compose.yml").read_text(encoding="utf-8"))

    service = compose["services"]["aiegis"]
    assert service["build"]["context"] == ".."
    assert service["read_only"] is True
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert "/var/lib/aiegis" in service["tmpfs"]
    assert "./policies:/etc/aiegis:ro" in service["volumes"]
