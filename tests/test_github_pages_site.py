from pathlib import Path

SITE = Path("docs/index.html")
CSS = Path("docs/site.css")


def test_github_pages_site_artifacts_exist() -> None:
    assert SITE.exists()
    assert CSS.exists()


def test_github_pages_site_has_required_sections() -> None:
    html = SITE.read_text(encoding="utf-8")

    for section_id in [
        'id="problem"',
        'id="architecture"',
        'id="guards"',
        'id="quick-start"',
        'id="production"',
        'id="docs"',
    ]:
        assert section_id in html


def test_github_pages_site_links_to_project_docs() -> None:
    html = SITE.read_text(encoding="utf-8")

    for link in [
        "https://github.com/syndicalt/aiegis/blob/master/README.md",
        "https://github.com/syndicalt/aiegis/blob/master/docs/deployment-runbook.md",
        "https://github.com/syndicalt/aiegis/blob/master/docs/security-assumptions.md",
        "https://github.com/syndicalt/aiegis/blob/master/docs/production-readiness.md",
        "https://github.com/syndicalt/aiegis/blob/master/examples/policies.yaml",
    ]:
        assert link in html


def test_github_pages_site_does_not_link_outside_pages_root() -> None:
    html = SITE.read_text(encoding="utf-8")

    assert 'href="../README.md"' not in html
    assert 'href="../examples/policies.yaml"' not in html


def test_github_pages_site_uses_concrete_security_language() -> None:
    html = SITE.read_text(encoding="utf-8").lower()

    for phrase in [
        "indirect prompt injection",
        "memory poisoning",
        "mcp stdio proxy",
        "eventloom",
        "audit log",
        "approval queue",
    ]:
        assert phrase in html


def test_github_pages_site_avoids_generic_ai_saas_copy() -> None:
    html = SITE.read_text(encoding="utf-8").lower()

    forbidden = [
        "unlock your ai workforce",
        "10x productivity",
        "supercharge your agents",
        "autonomous workforce",
    ]
    for phrase in forbidden:
        assert phrase not in html
