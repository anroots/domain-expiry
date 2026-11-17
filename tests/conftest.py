from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "whois"


@pytest.fixture
def whois_text():
    def load(name: str) -> str:
        return (FIXTURES / f"{name}.txt").read_text()

    return load
