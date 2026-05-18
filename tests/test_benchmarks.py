import json
import subprocess
import sys
from pathlib import Path

BENCHMARK_RUNNER = Path("benchmarks/run.py")
CORPUS_DIR = Path("benchmarks/corpus")


def test_benchmark_runner_reports_all_surfaces() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(BENCHMARK_RUNNER),
            "--iterations",
            "1",
            "--json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)

    assert payload["schema_version"] == 1
    surface_names = {benchmark["surface"] for benchmark in payload["benchmarks"]}
    assert {"core_guard", "boundary_decision", "audit_overhead", "cli_smoke"} <= surface_names
    assert all(benchmark["iterations"] == 1 for benchmark in payload["benchmarks"])
    assert all(benchmark["median_ms"] >= 0 for benchmark in payload["benchmarks"])
    assert all(benchmark["ops_per_sec"] >= 0 for benchmark in payload["benchmarks"])


def test_benchmark_corpus_contains_named_inputs_for_core_surfaces() -> None:
    for relative_path in [
        "html-small.html",
        "html-large.html",
        "email-multipart.eml",
        "memory-poisoning.txt",
        "document-text.txt",
        "output-secret.txt",
    ]:
        corpus_file = CORPUS_DIR / relative_path
        assert corpus_file.exists()
        assert corpus_file.read_text(encoding="utf-8").strip()


def test_readme_documents_benchmark_command() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")

    assert "## Benchmarks" in readme
    assert "python benchmarks/run.py --json" in readme
