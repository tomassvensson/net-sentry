"""JWT authentication for the Net Sentry API.

Provides:
- Token creation and validation using PyJWT (MIT licence).
- A FastAPI dependency ``require_auth`` that is a no-op when auth is
  disabled (``api.auth_enabled = false`` in config, which is the default).
- ``/api/v1/auth/token`` login endpoint (OAuth2 password flow).

Defaults
--------
auth_enabled: false  — all endpoints are public; no token needed.

To enable auth, add to config.yaml::

    api:
      auth_enabled: true
      jwt_secret: "<long-random-string>"   # preferably NET_SENTRY_JWT_SECRET
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
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import quote

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer

logger = logging.getLogger(__name__)

# Lazy imports — only required when auth is enabled.
# This avoids hard-failing if PyJWT / bcrypt are not installed
# while auth is disabled (default).
_jwt: Any = None
_bcrypt: Any = None

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)
ACCESS_COOKIE_NAME = "net_sentry_access_token"
_DUMMY_PASSWORD_HASH = "$2b$12$KvScd62IQgvmRNUtGL3g/eq2yyO/fMu8sK1aKPuR.CFHL5ciIJC1S"


def _load_jwt() -> Any:
    global _jwt  # noqa: PLW0603
    if _jwt is None:
        try:
            import jwt as jwt_module

            _jwt = jwt_module
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("PyJWT is required for JWT auth. Install it with: pip install PyJWT") from exc
    return _jwt


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
    jwt_module = _load_jwt()
    payload = dict(data)
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise ValueError("JWT access tokens require a non-empty 'sub' claim")
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=expires_minutes)
    payload["exp"] = expire
    payload["iat"] = now
    payload["jti"] = str(uuid.uuid4())
    payload["type"] = "access"
    return cast("str", jwt_module.encode(payload, secret, algorithm=algorithm))


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
    jwt_module = _load_jwt()
    try:
        claims = cast(
            "dict[str, Any]",
            jwt_module.decode(
                token,
                secret,
                algorithms=[algorithm],
                options={"require": ["sub", "exp", "iat", "jti", "type"]},
            ),
        )
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise jwt_module.InvalidTokenError("Missing or invalid subject")
        if claims.get("type") != "access":
            raise jwt_module.InvalidTokenError("Invalid token type")
        return claims
    except jwt_module.PyJWTError as exc:
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
_cookie_secure: bool = False


def configure_auth(
    enabled: bool,
    secret: str,
    algorithm: str,
    expire_minutes: int,
    users: dict[str, str],
    cookie_secure: bool = False,
) -> None:
    """Inject auth configuration from AppConfig into this module.

    Called once during application startup.
    """
    global _auth_enabled, _jwt_secret, _jwt_algorithm, _jwt_expire_minutes, _api_users, _cookie_secure  # noqa: PLW0603
    _auth_enabled = enabled
    _jwt_secret = secret
    _jwt_algorithm = algorithm
    _jwt_expire_minutes = expire_minutes
    _api_users = dict(users)
    _cookie_secure = cookie_secure
    if enabled:
        logger.info("JWT auth enabled (algorithm=%s, expire=%d min)", algorithm, expire_minutes)
    else:
        logger.info("JWT auth disabled — all API endpoints are public")


def _resolve_request_token(request: Request, bearer_token: str | None) -> str | None:
    """Resolve a bearer token first, then the secure browser-session cookie."""
    return bearer_token or request.cookies.get(ACCESS_COOKIE_NAME)


def require_auth(request: Request, token: str | None = Depends(oauth2_scheme)) -> str | None:
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
    resolved_token = _resolve_request_token(request, token)
    if not resolved_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    claims = decode_access_token(resolved_token, _jwt_secret, _jwt_algorithm)
    username = cast("str", claims["sub"])
    if username not in _api_users:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token user is no longer active",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username


def require_ui_auth(request: Request, token: str | None = Depends(oauth2_scheme)) -> str | None:
    """Protect browser pages and redirect unauthenticated users to login."""
    try:
        return require_auth(request=request, token=token)
    except HTTPException as exc:
        if exc.status_code != status.HTTP_401_UNAUTHORIZED:
            raise
        next_path = quote(request.url.path, safe="/")
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            detail="Login required",
            headers={"Location": f"/login?next={next_path}"},
        ) from exc


def authenticate_user(username: str, password: str) -> bool:
    """Verify username/password against the configured api_users dict.

    Args:
        username: Submitted username.
        password: Submitted plain-text password.

    Returns:
        True if credentials are valid.
    """
    password_hash = _api_users.get(username, _DUMMY_PASSWORD_HASH)
    valid = verify_password(password, password_hash)
    return valid and username in _api_users


def get_jwt_expire_minutes() -> int:
    """Return the configured JWT expiry duration."""
    return _jwt_expire_minutes


def issue_access_token(username: str) -> str:
    """Issue an access token using the active runtime configuration."""
    return create_access_token(
        {"sub": username},
        secret=_jwt_secret,
        algorithm=_jwt_algorithm,
        expires_minutes=_jwt_expire_minutes,
    )


def is_auth_enabled() -> bool:
    """Return whether runtime authentication is enabled."""
    return _auth_enabled


def is_cookie_secure() -> bool:
    """Return whether browser cookies must carry the Secure attribute."""
    return _cookie_secure
