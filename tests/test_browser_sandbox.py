from pathlib import Path

import pytest

from aiegis.browser_sandbox import BrowserRenderPolicy, BrowserRenderRequest, build_render_command


def test_build_render_command_requires_sandbox_wrapper() -> None:
    with pytest.raises(ValueError, match="sandbox_command"):
        BrowserRenderPolicy(sandbox_command=(), browser_command=("chromium",))


def test_build_render_command_uses_ephemeral_profile_and_cache_paths() -> None:
    command = build_render_command(
        BrowserRenderRequest(
            input_path=Path("/tmp/input.html"),
            output_path=Path("/tmp/output.pdf"),
            workspace=Path("/tmp/aiegis-render"),
        ),
        BrowserRenderPolicy(
            sandbox_command=("bwrap", "--unshare-all"),
            browser_command=("chromium",),
        ),
    )

    assert command.argv == (
        "bwrap",
        "--unshare-all",
        "chromium",
        "--headless=new",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-extensions",
        "--disable-default-apps",
        "--no-first-run",
        "--user-data-dir=/tmp/aiegis-render/profile",
        "--disk-cache-dir=/tmp/aiegis-render/cache",
        "--print-to-pdf=/tmp/output.pdf",
        "file:///tmp/input.html",
    )
    assert command.profile_dir == Path("/tmp/aiegis-render/profile")
    assert command.cache_dir == Path("/tmp/aiegis-render/cache")


def test_build_render_command_can_allow_network_explicitly() -> None:
    command = build_render_command(
        BrowserRenderRequest(
            input_path=Path("/tmp/input.html"),
            output_path=Path("/tmp/output.pdf"),
            workspace=Path("/tmp/aiegis-render"),
        ),
        BrowserRenderPolicy(
            sandbox_command=("firejail", "--private"),
            browser_command=("chromium",),
            allow_network=True,
        ),
    )

    assert "--disable-background-networking" not in command.argv
    assert command.argv[:3] == ("firejail", "--private", "chromium")


def test_build_render_command_rejects_remote_input_path() -> None:
    with pytest.raises(ValueError, match="local file"):
        BrowserRenderRequest(
            input_path=Path("https://example.test/page.html"),
            output_path=Path("/tmp/output.pdf"),
            workspace=Path("/tmp/aiegis-render"),
        )
