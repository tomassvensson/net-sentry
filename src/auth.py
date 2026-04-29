"""JWT authentication for the Net Sentry API.

Provides:
- Token creation and validation using python-jose (MIT licence).
- A FastAPI dependency ``require_auth`` that is a no-op when auth is
  disabled (``api.auth_enabled = false`` in config, which is the default).
- ``/api/v1/auth/token`` login endpoint (OAuth2 password flow).

Defaults
--------
auth_enabled: false  — all endpoints are public; no token needed.

To enable auth, add to config.yaml::

    api:
      auth_enabled: true
      jwt_secret: "<long-random-string>"   # also settable via BTWIFI_JWT_SECRET env var
      jwt_expire_minutes: 60
      api_users:
        admin: "$2b$12$..."   # bcrypt hash; see comment in ApiConfig

Generate a password hash::

    python -c "import bcrypt; print(bcrypt.hashpw(b'mypassword', bcrypt.gensalt()).decode())"

Obtain a token::

    curl -X POST http://localhost:8000/api/v1/auth/token \\
         -d "username=admin&password=mypassword"

Use the token::

    curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/devices
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

logger = logging.getLogger(__name__)

# Lazy imports — only required when auth is enabled.
# This avoids hard-failing if python-jose / bcrypt are not installed
# while auth is disabled (default).
_jose_jwt: Any = None
_bcrypt: Any = None

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)


def _load_jose() -> Any:
    global _jose_jwt  # noqa: PLW0603
    if _jose_jwt is None:
        try:
            from jose import jwt as jose_jwt  # noqa: F401

            _jose_jwt = jose_jwt
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "python-jose is required for JWT auth. Install it with: pip install python-jose[cryptography]"
            ) from exc
    return _jose_jwt


def _load_bcrypt() -> Any:
    global _bcrypt  # noqa: PLW0603
    if _bcrypt is None:
        try:
            import bcrypt as _bcrypt_mod

            _bcrypt = _bcrypt_mod
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("bcrypt is required for password hashing. Install it with: pip install bcrypt") from exc
    return _bcrypt


def create_access_token(
    data: dict[str, Any],
    secret: str,
    algorithm: str = "HS256",
    expires_minutes: int = 60,
) -> str:
    """Create a signed JWT access token.

    Args:
        data: Claims payload (e.g. ``{"sub": "username"}``).
        secret: Signing secret.
        algorithm: JWT algorithm (default HS256).
        expires_minutes: Token lifetime in minutes.

    Returns:
        Encoded JWT string.
    """
    jose_jwt = _load_jose()
    payload = dict(data)
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    payload["exp"] = expire
    return cast("str", jose_jwt.encode(payload, secret, algorithm=algorithm))


def decode_access_token(token: str, secret: str, algorithm: str = "HS256") -> dict[str, Any]:
    """Decode and validate a JWT access token.

    Args:
        token: Encoded JWT string.
        secret: Signing secret.
        algorithm: JWT algorithm.

    Returns:
        Decoded claims payload.

    Raises:
        HTTPException 401: If the token is invalid or expired.
    """
    jose_jwt = _load_jose()
    try:
        from jose import JWTError

        return cast("dict[str, Any]", jose_jwt.decode(token, secret, algorithms=[algorithm]))
    except JWTError as exc:
        logger.debug("JWT decode error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain-text password against a bcrypt hash.

    Args:
        plain: Plain-text password.
        hashed: bcrypt hash string.

    Returns:
        True if the password matches.
    """
    bcrypt = _load_bcrypt()
    try:
        return cast("bool", bcrypt.checkpw(plain.encode(), hashed.encode()))
    except Exception:
        logger.debug("bcrypt.checkpw failed", exc_info=True)
        return False


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

# Injected at app startup by configure_auth().
_auth_enabled: bool = False
_jwt_secret: str = ""
_jwt_algorithm: str = "HS256"
_jwt_expire_minutes: int = 60
_api_users: dict[str, str] = {}


def configure_auth(
    enabled: bool,
    secret: str,
    algorithm: str,
    expire_minutes: int,
    users: dict[str, str],
) -> None:
    """Inject auth configuration from AppConfig into this module.

    Called once during application startup.
    """
    global _auth_enabled, _jwt_secret, _jwt_algorithm, _jwt_expire_minutes, _api_users  # noqa: PLW0603
    _auth_enabled = enabled
    _jwt_secret = secret
    _jwt_algorithm = algorithm
    _jwt_expire_minutes = expire_minutes
    _api_users = users
    if enabled:
        logger.info("JWT auth enabled (algorithm=%s, expire=%d min)", algorithm, expire_minutes)
    else:
        logger.info("JWT auth disabled — all API endpoints are public")


def require_auth(token: str | None = Depends(oauth2_scheme)) -> str | None:
    """FastAPI dependency: validate Bearer token when auth is enabled.

    When ``auth_enabled=false`` (default) this is a no-op and returns ``None``.

    Args:
        token: Bearer token extracted from the Authorization header.

    Returns:
        Username from the token, or None when auth is disabled.

    Raises:
        HTTPException 401: When auth is enabled and no valid token is provided.
    """
    if not _auth_enabled:
        return None
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    claims = decode_access_token(token, _jwt_secret, _jwt_algorithm)
    return claims.get("sub")


def authenticate_user(username: str, password: str) -> bool:
    """Verify username/password against the configured api_users dict.

    Args:
        username: Submitted username.
        password: Submitted plain-text password.

    Returns:
        True if credentials are valid.
    """
    if username not in _api_users:
        return False
    return verify_password(password, _api_users[username])


def get_jwt_expire_minutes() -> int:
    """Return the configured JWT expiry duration."""
    return _jwt_expire_minutes
