from pathlib import Path

from cli import load_samples, samples_path


def test_samples_file_exists():
    assert samples_path().is_file()


def test_samples_cover_core_attack_types():
    samples = load_samples()
    names = {item["name"] for item in samples}
    assert {"benign_search", "xss", "sql_injection", "xxe"} <= names
    for item in samples:
        assert item["payload"].strip()
        assert "expect_type" in item
