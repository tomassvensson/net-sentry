"""Tests for src/auth.py — JWT authentication helpers."""

import importlib

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reload_auth(**overrides):
    """Reload auth module with injected module-level state."""
    import src.auth as auth_mod

    importlib.reload(auth_mod)
    for key, val in overrides.items():
        setattr(auth_mod, key, val)
    return auth_mod


# ---------------------------------------------------------------------------
# compute_confidence / evidence
# ---------------------------------------------------------------------------


def test_create_and_decode_access_token():
    """Round-trip: encode then decode a token and recover the subject."""
    from src.auth import create_access_token, decode_access_token

    secret = "test-secret"
    token = create_access_token({"sub": "alice"}, secret=secret, algorithm="HS256", expires_minutes=10)
    claims = decode_access_token(token, secret=secret, algorithm="HS256")
    assert claims["sub"] == "alice"


def test_decode_invalid_token_raises():
    """decode_access_token raises HTTP 401 for a garbage token."""
    from fastapi import HTTPException

    from src.auth import decode_access_token

    with pytest.raises(HTTPException) as exc_info:
        decode_access_token("not.a.real.token", secret="s", algorithm="HS256")
    assert exc_info.value.status_code == 401


def test_decode_wrong_secret_raises():
    """decode_access_token raises HTTP 401 when secret does not match."""
    from fastapi import HTTPException

    from src.auth import create_access_token, decode_access_token

    token = create_access_token({"sub": "bob"}, secret="secret-a", algorithm="HS256", expires_minutes=5)
    with pytest.raises(HTTPException) as exc_info:
        decode_access_token(token, secret="secret-b", algorithm="HS256")
    assert exc_info.value.status_code == 401


def test_verify_password_correct():
    """verify_password returns True for a matching bcrypt hash."""
    import bcrypt  # type: ignore[import-untyped]

    from src.auth import verify_password

    hashed = bcrypt.hashpw(b"hunter2", bcrypt.gensalt()).decode()
    assert verify_password("hunter2", hashed) is True


def test_verify_password_wrong():
    """verify_password returns False when the password does not match."""
    import bcrypt  # type: ignore[import-untyped]

    from src.auth import verify_password

    hashed = bcrypt.hashpw(b"correct", bcrypt.gensalt()).decode()
    assert verify_password("wrong", hashed) is False


def test_authenticate_user_valid(monkeypatch):
    """authenticate_user returns True for valid credentials."""
    import bcrypt  # type: ignore[import-untyped]

    import src.auth as auth_mod

    hashed = bcrypt.hashpw(b"pass123", bcrypt.gensalt()).decode()
    monkeypatch.setattr(auth_mod, "_api_users", {"admin": hashed})
    assert auth_mod.authenticate_user("admin", "pass123") is True


def test_authenticate_user_wrong_password(monkeypatch):
    """authenticate_user returns False for incorrect password."""
    import bcrypt  # type: ignore[import-untyped]

    import src.auth as auth_mod

    hashed = bcrypt.hashpw(b"correct", bcrypt.gensalt()).decode()
    monkeypatch.setattr(auth_mod, "_api_users", {"user": hashed})
    assert auth_mod.authenticate_user("user", "wrong") is False


def test_authenticate_user_unknown_username(monkeypatch):
    """authenticate_user returns False for an unknown username."""
    import src.auth as auth_mod

    monkeypatch.setattr(auth_mod, "_api_users", {})
    assert auth_mod.authenticate_user("ghost", "anything") is False


def test_require_auth_disabled_returns_none(monkeypatch):
    """require_auth returns None when auth is disabled (default)."""
    import src.auth as auth_mod

    monkeypatch.setattr(auth_mod, "_auth_enabled", False)
    result = auth_mod.require_auth(token=None)
    assert result is None


def test_require_auth_enabled_no_token_raises(monkeypatch):
    """require_auth raises HTTP 401 when auth is on and no token given."""
    from fastapi import HTTPException

    import src.auth as auth_mod

    monkeypatch.setattr(auth_mod, "_auth_enabled", True)
    with pytest.raises(HTTPException) as exc_info:
        auth_mod.require_auth(token=None)
    assert exc_info.value.status_code == 401


def test_require_auth_enabled_valid_token(monkeypatch):
    """require_auth returns username when a valid token is provided."""
    import src.auth as auth_mod

    secret = "unit-test-secret"
    token = auth_mod.create_access_token({"sub": "admin"}, secret=secret, expires_minutes=5)
    monkeypatch.setattr(auth_mod, "_auth_enabled", True)
    monkeypatch.setattr(auth_mod, "_jwt_secret", secret)
    monkeypatch.setattr(auth_mod, "_jwt_algorithm", "HS256")

    result = auth_mod.require_auth(token=token)
    assert result == "admin"


def test_configure_auth_sets_state():
    """configure_auth correctly sets all module-level state variables."""
    import src.auth as auth_mod

    auth_mod.configure_auth(
        enabled=True,
        secret="my-secret",
        algorithm="HS256",
        expire_minutes=30,
        users={"u": "h"},
    )
    assert auth_mod._auth_enabled is True
    assert auth_mod._jwt_secret == "my-secret"
    assert auth_mod._jwt_expire_minutes == 30
    assert auth_mod._api_users == {"u": "h"}

    # Clean up — restore defaults
    auth_mod.configure_auth(enabled=False, secret="", algorithm="HS256", expire_minutes=60, users={})


def test_get_jwt_expire_minutes(monkeypatch):
    """get_jwt_expire_minutes returns the current expiry setting."""
    import src.auth as auth_mod

    monkeypatch.setattr(auth_mod, "_jwt_expire_minutes", 42)
    assert auth_mod.get_jwt_expire_minutes() == 42
