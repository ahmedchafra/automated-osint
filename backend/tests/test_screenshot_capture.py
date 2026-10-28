from pathlib import Path

import pytest

from app.services.screenshot_capture import _same_origin, storage_path


def test_screenshot_origin_matching_is_exact():
    assert _same_origin("https://app.example.com/style.css", "https://app.example.com/")
    assert not _same_origin("https://cdn.example.com/style.css", "https://app.example.com/")
    assert not _same_origin("http://app.example.com/style.css", "https://app.example.com/")
    assert not _same_origin("https://app.example.com:8443/", "https://app.example.com/")


def test_screenshot_storage_key_cannot_escape_root(tmp_path: Path):
    assert storage_path(tmp_path, "scan/evidence.png") == (tmp_path / "scan/evidence.png").resolve()
    with pytest.raises(ValueError, match="invalid screenshot storage key"):
        storage_path(tmp_path, "../outside.png")
