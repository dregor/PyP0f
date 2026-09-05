from pyp0f.config import _env


def test_env_returns_default_when_unset(monkeypatch):
    monkeypatch.delenv("PYP0F_DOES_NOT_EXIST", raising=False)
    assert _env("PYP0F_DOES_NOT_EXIST", "fallback") == "fallback"


def test_env_returns_value_when_set(monkeypatch):
    monkeypatch.setenv("PYP0F_SOME_VAR", "custom-value")
    assert _env("PYP0F_SOME_VAR", "fallback") == "custom-value"


def test_env_empty_string_is_not_treated_as_unset(monkeypatch):
    # os.environ.get() only falls back on a *missing* key, not an empty one -
    # an explicitly empty env var should be returned as-is, not replaced.
    monkeypatch.setenv("PYP0F_EMPTY_VAR", "")
    assert _env("PYP0F_EMPTY_VAR", "fallback") == ""
