from pathlib import Path

SITE = Path("docs/index.html")
CSS = Path("docs/site.css")
SOCIAL_IMAGE = Path("docs/assets/pg-graph.png")
BENCHMARKS = Path("docs/benchmarks.html")
BENCHMARK_BASELINE = Path("docs/assets/benchmarks/baseline-2026-05-18.json")


def test_github_pages_site_artifacts_exist() -> None:
    assert SITE.exists()
    assert CSS.exists()
    assert SOCIAL_IMAGE.exists()
    assert BENCHMARKS.exists()
    assert BENCHMARK_BASELINE.exists()


def test_github_pages_site_uses_pg_social_media_image() -> None:
    html = SITE.read_text(encoding="utf-8")

    for tag in [
        '<meta property="og:image" content="assets/pg-graph.png">',
        '<meta name="twitter:card" content="summary_large_image">',
        '<meta name="twitter:image" content="assets/pg-graph.png">',
    ]:
        assert tag in html


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


def test_github_pages_site_links_to_benchmarks_page() -> None:
    html = SITE.read_text(encoding="utf-8")

    assert 'href="benchmarks.html"' in html


def test_benchmarks_page_is_transparent_about_methodology() -> None:
    html = BENCHMARKS.read_text(encoding="utf-8")

    for phrase in [
        "python benchmarks/run.py --json",
        "100 iterations",
        "Python 3.13.13",
        "12th Gen Intel(R) Core(TM) i7-12700H",
        "CLI timings include Python subprocess startup",
        "No competitor comparison is implied",
        "baseline-2026-05-18.json",
    ]:
        assert phrase in html


def test_benchmarks_page_publishes_all_surfaces() -> None:
    html = BENCHMARKS.read_text(encoding="utf-8")

    for surface in [
        "Core guard throughput",
        "Boundary decision latency",
        "Audit overhead",
        "CLI smoke timing",
    ]:
        assert surface in html


def test_benchmarks_page_avoids_unsubstantiated_claims() -> None:
    html = BENCHMARKS.read_text(encoding="utf-8").lower()

    for phrase in [
        "fastest",
        "faster than",
        "industry leading",
        "zero overhead",
    ]:
        assert phrase not in html


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
