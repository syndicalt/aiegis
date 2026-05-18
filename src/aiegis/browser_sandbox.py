from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class BrowserRenderPolicy:
    sandbox_command: tuple[str, ...]
    browser_command: tuple[str, ...]
    allow_network: bool = False

    def __post_init__(self) -> None:
        if not self.sandbox_command:
            raise ValueError("sandbox_command must not be empty.")
        if not self.browser_command:
            raise ValueError("browser_command must not be empty.")


@dataclass(frozen=True, slots=True)
class BrowserRenderRequest:
    input_path: Path
    output_path: Path
    workspace: Path

    def __post_init__(self) -> None:
        parsed = urlparse(str(self.input_path))
        if parsed.scheme in {"http", "https"}:
            raise ValueError("Browser render input must be a local file path.")


@dataclass(frozen=True, slots=True)
class BrowserRenderCommand:
    argv: tuple[str, ...]
    profile_dir: Path
    cache_dir: Path


def build_render_command(
    request: BrowserRenderRequest,
    policy: BrowserRenderPolicy,
) -> BrowserRenderCommand:
    profile_dir = request.workspace / "profile"
    cache_dir = request.workspace / "cache"
    browser_flags = [
        "--headless=new",
        "--disable-sync",
        "--disable-extensions",
        "--disable-default-apps",
        "--no-first-run",
        f"--user-data-dir={profile_dir}",
        f"--disk-cache-dir={cache_dir}",
        f"--print-to-pdf={request.output_path}",
        request.input_path.absolute().as_uri(),
    ]
    if not policy.allow_network:
        browser_flags.insert(1, "--disable-background-networking")

    return BrowserRenderCommand(
        argv=policy.sandbox_command + policy.browser_command + tuple(browser_flags),
        profile_dir=profile_dir,
        cache_dir=cache_dir,
    )
