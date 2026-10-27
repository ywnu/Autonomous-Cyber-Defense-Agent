"""Regression tests for ai/config.py. They never read the developer's real .env."""

import os

import pytest

from ai import config
from ai.config import DEFAULT_MAX_OUTPUT_TOKENS, get_settings, load_dotenv


@pytest.fixture
def clean_env(monkeypatch):
    for name in ("AI_TEST_DUP", "NEBIUS_MAX_OUTPUT_TOKENS"):
        monkeypatch.delenv(name, raising=False)
    yield monkeypatch
    os.environ.pop("AI_TEST_DUP", None)


def test_duplicate_key_in_dotenv_last_value_wins(tmp_path, clean_env):
    # Regression: NEBIUS_MAX_OUTPUT_TOKENS appeared twice and editing the later line had no effect.
    env = tmp_path / ".env"
    env.write_text("AI_TEST_DUP=first\nOTHER=x\nAI_TEST_DUP=second\n", encoding="utf-8")
    load_dotenv(env)
    assert os.environ["AI_TEST_DUP"] == "second"


def test_real_environment_variable_still_wins_over_duplicates(tmp_path, clean_env):
    env = tmp_path / ".env"
    env.write_text("AI_TEST_DUP=first\nAI_TEST_DUP=second\n", encoding="utf-8")
    clean_env.setenv("AI_TEST_DUP", "from_env")
    load_dotenv(env)
    assert os.environ["AI_TEST_DUP"] == "from_env"


def test_default_max_output_tokens_fits_the_nemotron_reply(clean_env):
    # Regression: the old default (4096) made the live Nemotron reply get cut off and rejected.
    clean_env.setattr(config, "load_dotenv", lambda *args, **kwargs: None)
    assert DEFAULT_MAX_OUTPUT_TOKENS == 16384
    assert get_settings().max_output_tokens == 16384


@pytest.mark.parametrize("value, expected", [("8192", 8192), ("1", 256), ("999999", 32768), ("bad", 16384)])
def test_max_output_tokens_override_is_clamped(clean_env, value, expected):
    clean_env.setattr(config, "load_dotenv", lambda *args, **kwargs: None)
    clean_env.setenv("NEBIUS_MAX_OUTPUT_TOKENS", value)
    assert get_settings().max_output_tokens == expected
