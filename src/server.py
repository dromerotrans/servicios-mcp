"""
servicios-mcp — servidor MCP remoto (Streamable HTTP) que expone, de solo
lectura, la API de SAP Business One Service Layer, la API de contratos
de Cisco (CCWR) y la API de estado de órdenes de Cisco (CCW) usadas por
Hermes.

Diseñado para correr como un Deployment propio en el namespace `hermes`
de OKD, detrás de una Route pública con TLS, para que un cliente externo
(otro Claude, en otra cuenta) pueda agregarlo como conector MCP remoto y
consultar los mismos datos sin tener acceso directo a las credenciales
reales de SAP/Cisco ni al clúster.

Autenticación: bearer token simple (`Authorization: Bearer <token>`),
verificado contra un store de tokens persistido en disco (`TOKENS_FILE`,
gestionable desde el panel /admin sin redeploy — ver TokenStore). En el
primer arranque sobre un volumen vacío se siembra desde la variable de
entorno legacy MCP_ACCESS_TOKENS ("token1:etiqueta1,token2:etiqueta2").
Cada token es independiente de las credenciales reales de SAP/Cisco —
se puede generar/revocar desde /admin sin tocar nada más.

Panel /admin: HTML+JS embebido, sin dependencias nuevas, protegido con
HTTP Basic Auth (ADMIN_USER/ADMIN_PASSWORD) — distinto de los tokens
Bearer del MCP. Hereda la whitelist de IP y el TLS de la Route.

OAuth2 (para Claude Desktop): además del uso directo del Bearer token
(Claude Code CLI), el servidor actúa como Authorization Server OAuth 2.1
(RFC 8414/9728/7591, usando el soporte nativo del SDK `mcp.server.auth`)
para que el conector se pueda agregar desde el panel de conectores de
Claude Desktop/Claude.ai, que solo sabe hablar OAuth. Registro dinámico
de clientes (DCR) habilitado — no hace falta que Diego genere Client
ID/Secret a mano. El "login" en el navegador (`/oauth/login`) pide el
mismo token personal que ya usa Claude Code — no es un usuario/password
nuevo. El access_token que se emite ES ese mismo token personal (revocable
desde /admin en cualquier momento), no uno nuevo con expiración propia.

Reglas heredadas del skill sap-service-layer de Hermes (no negociables):
SOLO LECTURA contra SAP. El servidor nunca arma un POST/PATCH/DELETE
contra una entidad de datos — las únicas llamadas POST son Login/Logout
de sesión SAP y el token endpoint OAuth2 de Cisco.
"""

import base64
import collections
import contextlib
import contextvars
import json
import logging
import os
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timezone

from pydantic import AnyHttpUrl

from mcp.server.auth.provider import (
    AccessToken as MCPAccessToken,
    AuthorizationCode as MCPAuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.routes import (
    build_resource_metadata_url,
    create_auth_routes,
    create_protected_resource_routes,
)
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.types import ASGIApp

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("hermes-mcp")

# ---------------------------------------------------------------------------
# Config (todo por variable de entorno — ver manifests/hermes-mcp/secret.yaml)
# ---------------------------------------------------------------------------

SAP_BASE_URL = os.environ.get("SAP_BASE_URL", "https://sap.trans.com.ar:50000/b1s/v1")
SAP_COMPANY_DB = os.environ["SAP_SL_COMPANY_DB"]
SAP_USERNAME = os.environ["SAP_SL_USERNAME"]
SAP_PASSWORD = os.environ["SAP_SL_PASSWORD"]

CCWR_TOKEN_URL = os.environ.get("CCWR_TOKEN_URL", "https://id.cisco.com/oauth2/default/v1/token")
CCWR_API_URL = os.environ.get(
    "CCWR_API_URL", "https://apix.cisco.com/ccw/renewals/api/v1.0/search/lines"
)
CCWR_CLIENT_ID = os.environ.get("CCWR_CLIENT_ID", "")
CCWR_CLIENT_SECRET = os.environ.get("CCWR_CLIENT_SECRET", "")

# CCW — Cisco B2B Commerce GraphQL API (estado de órdenes de compra Cisco).
# Distinto de CCWR (contratos de servicio) — API y credenciales separadas,
# mismo token endpoint de Cisco. Ver deploy/skill-order-status-modern-graphql-2026-08-06.md.
CCW_TOKEN_URL = os.environ.get("CCW_TOKEN_URL", "https://id.cisco.com/oauth2/default/v1/token")
CCW_API_URL = os.environ.get("CCW_API_URL", "https://capi.cisco.com/commerce/apis")
CCW_CLIENT_ID = os.environ.get("CCW_CLIENT_ID", "")
CCW_CLIENT_SECRET = os.environ.get("CCW_CLIENT_SECRET", "")

# Ruta del store persistente de tokens (PVC local, no NFS — mismo patrón de
# storage que el resto del proyecto). "token1:etiqueta1,token2:etiqueta2" en
# MCP_ACCESS_TOKENS se usa SOLO para migrar/sembrar el store la primera vez
# que arranca sobre un volumen vacío — de ahí en más el archivo es la fuente
# de verdad y se gestiona desde el panel /admin, sin redeploy.
TOKENS_FILE = os.environ.get("TOKENS_FILE", "/data/tokens.json")
ADMIN_USER = os.environ.get("ADMIN_USER", "diego")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# OAuth2 (Authorization Server) — para que Claude Desktop pueda agregar el
# conector desde su panel (solo sabe hablar OAuth, no Bearer token fijo).
# URL pública canónica del servidor — debe matchear el hostname real de la
# Route (mismo que transport_security.allowed_hosts más abajo).
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://servicios-mcp.trans.com.ar").rstrip("/")
OAUTH_CLIENTS_FILE = os.environ.get("OAUTH_CLIENTS_FILE", "/data/oauth_clients.json")

OAUTH_ISSUER_URL = AnyHttpUrl(PUBLIC_BASE_URL)
OAUTH_RESOURCE_URL = AnyHttpUrl(f"{PUBLIC_BASE_URL}/mcp")
# URL de metadata (RFC 9728) que el cliente MCP debe consultar tras un 401 —
# va en el header WWW-Authenticate de cada 401 de /mcp.
RESOURCE_METADATA_URL = build_resource_metadata_url(OAUTH_RESOURCE_URL)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _seed_tokens_from_env() -> dict[str, dict]:
    raw = os.environ.get("MCP_ACCESS_TOKENS", "")
    seeded: dict[str, dict] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        tok, _, label = pair.partition(":")
        tok = tok.strip()
        label = label.strip() or "sin-etiqueta"
        seeded[tok] = {
            "label": label,
            "created_at": _now_iso(),
            "last_used_at": None,
            "call_count": 0,
        }
    return seeded


class TokenStore:
    """Store de tokens de acceso al MCP, persistido como JSON en un PVC local.

    Gestionable en caliente desde el panel /admin (agregar/revocar) sin
    redeploy ni restart. Si el archivo no existe todavía (primer arranque
    sobre un volumen nuevo), se siembra una única vez desde la variable de
    entorno MCP_ACCESS_TOKENS (compatibilidad con el esquema anterior).
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}
        self._load_or_seed()

    def _load_or_seed(self) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        if os.path.exists(self._path):
            with open(self._path) as f:
                self._data = json.load(f)
            return
        self._data = _seed_tokens_from_env()
        self._save()
        log.info(
            "TokenStore sembrado desde MCP_ACCESS_TOKENS (%d token/s) en %s",
            len(self._data), self._path,
        )

    def _save(self) -> None:
        tmp = f"{self._path}.tmp"
        with open(tmp, "w") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self._path)

    def check(self, token: str) -> str | None:
        """Valida un token y, si es válido, actualiza sus métricas de uso."""
        with self._lock:
            info = self._data.get(token)
            if not info:
                return None
            info["last_used_at"] = _now_iso()
            info["call_count"] = info.get("call_count", 0) + 1
            self._save()
            return info["label"]

    def list(self) -> list[dict]:
        with self._lock:
            return [
                {"token": tok, **info}
                for tok, info in sorted(self._data.items(), key=lambda kv: kv[1]["created_at"])
            ]

    def add(self, label: str) -> str:
        with self._lock:
            token = "tok_" + secrets.token_urlsafe(24)
            self._data[token] = {
                "label": label,
                "created_at": _now_iso(),
                "last_used_at": None,
                "call_count": 0,
            }
            self._save()
            return token

    def revoke(self, label: str) -> int:
        with self._lock:
            to_delete = [tok for tok, info in self._data.items() if info["label"] == label]
            for tok in to_delete:
                del self._data[tok]
            if to_delete:
                self._save()
            return len(to_delete)


class OAuthClientStore:
    """Store de clientes OAuth registrados dinámicamente (RFC 7591), persistido
    como JSON en el mismo PVC que TokenStore. No guarda identidad de personas
    — solo qué apps (ej. "Claude") se registraron como clientes OAuth; la
    identidad real de la persona se resuelve en /oauth/login contra
    TokenStore, igual que con Claude Code.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        if os.path.exists(self._path):
            with open(self._path) as f:
                self._data = json.load(f)

    def _save(self) -> None:
        tmp = f"{self._path}.tmp"
        with open(tmp, "w") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self._path)

    def get(self, client_id: str) -> dict | None:
        with self._lock:
            return self._data.get(client_id)

    def save(self, client_id: str, client_info: dict) -> None:
        with self._lock:
            self._data[client_id] = client_info
            self._save()


oauth_client_store = OAuthClientStore(OAUTH_CLIENTS_FILE)

token_store = TokenStore(TOKENS_FILE)

if not token_store.list():
    raise RuntimeError(
        "El store de tokens está vacío — el servidor no puede arrancar sin al menos un "
        "token de acceso configurado (evita quedar abierto sin auth por error de "
        "despliegue). Agregar uno vía MCP_ACCESS_TOKENS en el primer arranque, o directo "
        "en el panel /admin si el volumen ya existe."
    )

if not ADMIN_PASSWORD:
    raise RuntimeError(
        "ADMIN_PASSWORD vacío — el panel /admin no puede arrancar sin contraseña "
        "configurada (evita quedar abierto sin auth por error de despliegue)."
    )

MAX_TOP = 1000  # tope duro, evita que un $top gigante tire abajo el server o SAP

# Etiqueta del token (persona) e IP del request en curso, seteadas por
# BearerAuthMiddleware antes de despachar y leídas dentro de cada tool para
# poder loguear/auditar "qué token hizo qué, desde dónde" (no solo "qué
# token pegó qué path" — todas las tools comparten el mismo path /mcp).
current_token_label: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_token_label", default="?"
)
current_client_ip: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_client_ip", default="?"
)

# Ruta del registro de auditoría persistente (mismo PVC que TOKENS_FILE).
# Formato JSON Lines (un evento por línea, append-only) para poder tail-earlo
# con herramientas normales además de leerlo desde el panel /admin.
AUDIT_FILE = os.environ.get("AUDIT_FILE", "/data/audit.jsonl")
AUDIT_MAX_ENTRIES = 1000  # tope en memoria/panel — el archivo en disco no se poda


class AuditLog:
    """Registro de auditoría de solo-agregado: llamadas a tools y fallos de
    auth. Persiste en JSON Lines y mantiene una cola acotada en memoria para
    servir al panel /admin sin releer el archivo completo en cada request.
    """

    def __init__(self, path: str, maxlen: int = AUDIT_MAX_ENTRIES) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._entries: collections.deque = collections.deque(maxlen=maxlen)
        self._load_tail(maxlen)

    def _load_tail(self, maxlen: int) -> None:
        if not os.path.exists(self._path):
            return
        with open(self._path) as f:
            lines = f.readlines()[-maxlen:]
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                self._entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    def append(self, **fields) -> None:
        entry = {"ts": _now_iso(), **fields}
        with self._lock:
            self._entries.append(entry)
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            with open(self._path, "a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def list(self, limit: int = 200) -> list[dict]:
        with self._lock:
            items = list(self._entries)
        items.reverse()  # más reciente primero
        return items[: max(1, min(limit, AUDIT_MAX_ENTRIES))]


audit_log = AuditLog(AUDIT_FILE)


def _audit_tool_call(tool: str, **params) -> None:
    """Loguea (stdout, para `oc logs`) Y persiste (para el panel /admin) una
    llamada a una tool — quién (token/etiqueta), desde dónde (IP), qué tool,
    con qué parámetros principales."""
    label = current_token_label.get()
    ip = current_client_ip.get()
    log.info("TOOL_CALL tool=%s label=%s ip=%s params=%r", tool, label, ip, params)
    audit_log.append(event="tool_call", tool=tool, label=label, ip=ip, params=params)


def _audit_auth_fail(reason: str, ip: str, path: str) -> None:
    log.warning("AUTH_FAIL %s ip=%s path=%s", reason, ip, path)
    audit_log.append(event="auth_fail", reason=reason, ip=ip, path=path)


def _audit_oauth_login(label: str, ip: str, client_id: str, client_name: str | None) -> None:
    log.info("OAUTH_LOGIN_OK label=%s ip=%s client_id=%s client_name=%s", label, ip, client_id, client_name)
    audit_log.append(event="oauth_login", label=label, ip=ip, client_id=client_id, client_name=client_name)


# ---------------------------------------------------------------------------
# OAuth2 Authorization Server — permite agregar el conector desde Claude
# Desktop (que solo sabe hablar OAuth, no un Bearer token fijo). Implementa
# el Protocol OAuthAuthorizationServerProvider del SDK oficial de MCP; las
# rutas HTTP (/authorize, /token, /register, /.well-known/...) las genera y
# valida el SDK (PKCE, expiración de código, client_secret, etc. — no hay
# nada de eso hecho a mano acá). Lo único propio es /oauth/login: un
# formulario mínimo que pide el MISMO token personal que ya usa Claude Code
# — no crea una identidad ni una contraseña nueva. El access_token que se
# termina emitiendo ES ese token personal tal cual (revocable desde /admin
# en cualquier momento, sin expiración propia adicional).
# ---------------------------------------------------------------------------

_LOGIN_TTL_SECONDS = 600  # 10 min para completar el formulario de /oauth/login
_AUTH_CODE_TTL_SECONDS = 300  # 5 min para canjear el code por un token (RFC 6749 10.5)


class ServiciosMcpAuthorizationCode(MCPAuthorizationCode):
    """AuthorizationCode del SDK + los datos que servicios-mcp necesita para
    resolver el canje: el token personal real y su etiqueta (para loguear)."""

    personal_token: str
    label: str


class ServiciosMcpOAuthProvider:
    """Implementación mínima de OAuthAuthorizationServerProvider. No hay
    tercer proveedor de identidad: la persona se autentica pegando su propio
    token de servicios-mcp en /oauth/login."""

    def __init__(self, client_store: OAuthClientStore) -> None:
        self._clients = client_store
        self._lock = threading.Lock()
        self._pending_logins: dict[str, tuple[OAuthClientInformationFull, AuthorizationParams, float]] = {}
        self._codes: dict[str, ServiciosMcpAuthorizationCode] = {}

    # -- registro de clientes (RFC 7591) -----------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = self._clients.get(client_id)
        return OAuthClientInformationFull(**data) if data else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients.save(client_info.client_id, client_info.model_dump(mode="json", exclude_none=True))
        log.info(
            "OAUTH_CLIENT_REGISTERED client_id=%s client_name=%s",
            client_info.client_id, client_info.client_name,
        )

    # -- authorize: no hay tercero, redirige a nuestro propio login --------

    def _gc_pending(self) -> None:
        now = time.time()
        expired = [k for k, (_, _, exp) in self._pending_logins.items() if exp < now]
        for k in expired:
            del self._pending_logins[k]

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        login_id = secrets.token_urlsafe(24)
        with self._lock:
            self._gc_pending()
            self._pending_logins[login_id] = (client, params, time.time() + _LOGIN_TTL_SECONDS)
        return f"/oauth/login?login_id={login_id}"

    def peek_pending_login(
        self, login_id: str
    ) -> tuple[OAuthClientInformationFull, AuthorizationParams] | None:
        with self._lock:
            self._gc_pending()
            entry = self._pending_logins.get(login_id)
        if not entry:
            return None
        client, params, _ = entry
        return client, params

    def consume_pending_login(
        self, login_id: str
    ) -> tuple[OAuthClientInformationFull, AuthorizationParams] | None:
        with self._lock:
            self._gc_pending()
            entry = self._pending_logins.pop(login_id, None)
        if not entry:
            return None
        client, params, _ = entry
        return client, params

    def issue_code(self, client: OAuthClientInformationFull, params: AuthorizationParams, personal_token: str, label: str) -> str:
        code = secrets.token_urlsafe(32)
        with self._lock:
            self._codes[code] = ServiciosMcpAuthorizationCode(
                code=code,
                scopes=params.scopes or [],
                expires_at=time.time() + _AUTH_CODE_TTL_SECONDS,
                client_id=client.client_id,
                code_challenge=params.code_challenge,
                redirect_uri=params.redirect_uri,
                redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
                resource=params.resource,
                personal_token=personal_token,
                label=label,
            )
        return code

    # -- intercambio code -> token (PKCE ya validado por el SDK antes de llamar acá) --

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> ServiciosMcpAuthorizationCode | None:
        with self._lock:
            code = self._codes.get(authorization_code)
        if code is None or code.client_id != client.client_id:
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: ServiciosMcpAuthorizationCode
    ) -> OAuthToken:
        with self._lock:
            self._codes.pop(authorization_code.code, None)
        return OAuthToken(
            access_token=authorization_code.personal_token,
            token_type="Bearer",
            expires_in=None,
            scope=" ".join(authorization_code.scopes) if authorization_code.scopes else None,
            refresh_token=None,
        )

    # -- refresh: no se emiten refresh tokens (el access_token ES el token
    # personal, de vida larga y revocable desde /admin) -------------------

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str):
        return None

    async def exchange_refresh_token(self, client, refresh_token, scopes) -> OAuthToken:
        raise TokenError(
            error="unsupported_grant_type",
            error_description="servicios-mcp no emite refresh tokens: el access_token no expira "
            "por sí solo, se revoca desde el panel /admin.",
        )

    # -- validación de access token (no la usa BearerAuthMiddleware, que
    # valida directo contra TokenStore; se implementa para cumplir el
    # Protocol del SDK por completitud) ------------------------------------

    async def load_access_token(self, token: str) -> MCPAccessToken | None:
        label = token_store.check(token)
        if not label:
            return None
        return MCPAccessToken(token=token, client_id="*", scopes=[], expires_at=None)

    async def revoke_token(self, token) -> None:
        pass  # la revocación real es desde /admin, sobre TokenStore


oauth_provider = ServiciosMcpOAuthProvider(oauth_client_store)


# ---------------------------------------------------------------------------
# Cliente SAP Service Layer — sesión con cookie, re-login automático
# ---------------------------------------------------------------------------


class SapClient:
    def __init__(self) -> None:
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE  # cert self-signed, igual que el skill original
        self._session_id: str | None = None
        self._last_login = 0.0

    def _login(self) -> None:
        body = json.dumps(
            {
                "CompanyDB": SAP_COMPANY_DB,
                "UserName": SAP_USERNAME,
                "Password": SAP_PASSWORD,
            }
        ).encode()
        req = urllib.request.Request(
            f"{SAP_BASE_URL}/Login",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15, context=self._ctx) as resp:
            data = json.loads(resp.read().decode())
        # SAP Service Layer set-cookie header trae B1SESSION; urllib no persiste
        # cookies solas, así que la extraemos a mano del header set-cookie.
        set_cookie = resp.headers.get_all("Set-Cookie") or []
        session_id = data.get("SessionId")
        cookie_parts = []
        for c in set_cookie:
            name = c.split("=", 1)[0].strip()
            if name in ("B1SESSION", "ROUTEID"):
                cookie_parts.append(c.split(";", 1)[0])
        if session_id and not any(p.startswith("B1SESSION=") for p in cookie_parts):
            cookie_parts.append(f"B1SESSION={session_id}")
        self._session_id = "; ".join(cookie_parts)
        self._last_login = time.time()
        log.info("SAP login OK (SessionId=%s)", session_id)

    def _get(self, path: str, retry: bool = True) -> dict:
        if not self._session_id:
            self._login()
        req = urllib.request.Request(
            f"{SAP_BASE_URL}/{path}",
            headers={"Accept": "application/json", "Cookie": self._session_id},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=30, context=self._ctx) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code in (401, 403) and retry:
                log.info("SAP sesión vencida, re-login")
                self._session_id = None
                return self._get(path, retry=False)
            body = e.read().decode(errors="replace")
            raise RuntimeError(f"SAP HTTP {e.code}: {body[:500]}") from e

    def query(
        self,
        entity: str,
        select: str | None,
        filter_: str | None,
        orderby: str | None,
        top: int,
        skip: int,
    ) -> dict:
        top = max(1, min(top, MAX_TOP))
        params = {"$top": top, "$skip": max(0, skip)}
        if select:
            params["$select"] = select
        if filter_:
            params["$filter"] = filter_
        if orderby:
            params["$orderby"] = orderby
        qs = urllib.parse.urlencode(params, safe="$,()'")
        return self._get(f"{entity}?{qs}")

    def get_entity(self, entity: str, entry_id: str) -> dict:
        # entry_id puede ser numérico (DocEntry) o string entre comillas
        # (algunas entidades usan clave alfanumérica) — se pasa tal cual,
        # el llamador es responsable de citarlo si hace falta.
        return self._get(f"{entity}({entry_id})")


# ---------------------------------------------------------------------------
# Cliente Cisco CCWR — OAuth2 client_credentials, token cacheado
# ---------------------------------------------------------------------------


class CcwrClient:
    def __init__(self) -> None:
        self._token: str | None = None
        self._expires_at = 0.0

    def _get_token(self) -> str:
        if self._token and time.time() < self._expires_at - 30:
            return self._token
        body = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": CCWR_CLIENT_ID,
                "client_secret": CCWR_CLIENT_SECRET,
            }
        ).encode()
        req = urllib.request.Request(
            CCWR_TOKEN_URL,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        self._token = data["access_token"]
        self._expires_at = time.time() + int(data.get("expires_in", 3600))
        log.info("CCWR token OK, expira en %ss", data.get("expires_in"))
        return self._token

    def search(
        self,
        serial_numbers: list[str] | None,
        contract_numbers: list[str] | None,
        instance_numbers: list[str] | None,
        limit: int,
        offset: int,
    ) -> dict:
        token = self._get_token()
        body: dict = {"limit": max(1, min(limit, 1000)), "offset": max(0, offset)}
        if serial_numbers:
            body["serialNumbers"] = serial_numbers
        if contract_numbers:
            body["contractNumbers"] = contract_numbers
        if instance_numbers:
            body["instanceNumbers"] = instance_numbers
        req = urllib.request.Request(
            CCWR_API_URL,
            data=json.dumps(body).encode(),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                # Obligatorio (no documentado en el PDF de Cisco) — un UUID
                # nuevo por request. Ver deploy/skill-ccwr-contract-admin-2026-08-06.md.
                "Request-Id": str(uuid.uuid4()),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body_txt = e.read().decode(errors="replace")
            raise RuntimeError(f"CCWR HTTP {e.code}: {body_txt[:500]}") from e


# ---------------------------------------------------------------------------
# Cliente Cisco CCW — Commerce GraphQL, OAuth2 client_credentials, token cacheado
# ---------------------------------------------------------------------------


class CcwClient:
    def __init__(self) -> None:
        self._token: str | None = None
        self._expires_at = 0.0

    def _get_token(self) -> str:
        if self._token and time.time() < self._expires_at - 30:
            return self._token
        body = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": CCW_CLIENT_ID,
                "client_secret": CCW_CLIENT_SECRET,
            }
        ).encode()
        req = urllib.request.Request(
            CCW_TOKEN_URL,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        self._token = data["access_token"]
        self._expires_at = time.time() + int(data.get("expires_in", 3600))
        log.info("CCW token OK, expira en %ss", data.get("expires_in"))
        return self._token

    def get_order_details(
        self,
        order_search_key: str,
        order_search_value: str,
        page: int,
        page_size: int,
    ) -> dict:
        token = self._get_token()
        # sortByOrderCharacteristics es campo REQUERIDO por la API pese a no
        # figurar como tal en la doc oficial de Cisco — sin él, error de
        # validación. Ver deploy/skill-order-status-modern-graphql-2026-08-06.md.
        query = (
            "query GetOrderDetails { getOrderDetails(input: { orderSearchCriteria: "
            "{ orderSearchKey: %s, orderSearchValue: \"%s\" }, "
            "sortByOrderCharacteristics: ORDER_SUBMITTED_DATE, "
            "pagination: { page: %d, pageSize: %d, sortOrder: DESC } }) "
            "{ messages { code description } objects { id orderStatus "
            "metaData { createdOn } ciscoSalesOrderReference { ciscoSalesOrderId } "
            "buyerPurchaseOrderReference { purchaseOrderId } "
            "priceList { code description } lines { item { sku description } "
            "quantity { measurement unitOfMeasure } orderLineStatus "
            "financialDetails { extendedNetPrice { amount currency } } } } } }"
        ) % (order_search_key, order_search_value.replace('"', '\\"'), page, page_size)
        req = urllib.request.Request(
            CCW_API_URL,
            data=json.dumps({"query": query}).encode(),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body_txt = e.read().decode(errors="replace")
            raise RuntimeError(f"CCW HTTP {e.code}: {body_txt[:500]}") from e


sap = SapClient()
ccwr = CcwrClient()
ccw = CcwClient()


# ---------------------------------------------------------------------------
# Servidor MCP y tools
# ---------------------------------------------------------------------------

mcp_server = FastMCP(
    name="hermes-sap-ccwr",
    instructions=(
        "Herramientas de SOLO LECTURA contra SAP Business One (Service Layer), la API de "
        "contratos de servicio de Cisco (CCWR) y la API de estado de órdenes de Cisco (CCW) "
        "de Trans Industrias. Nunca hay escritura: todas las tools solo arman GET/consultas; "
        "no existe ninguna tool de creación, modificación o borrado. Usar sap_query para "
        "listar/filtrar documentos (Orders, DeliveryNotes, PurchaseOrders, "
        "PurchaseDeliveryNotes, BusinessPartners, etc. — ver la doc de entidades OData de "
        "SAP B1 Service Layer) y sap_get_entity cuando se necesite el detalle completo de UN "
        "documento puntual (por ejemplo para traer SerialNumbers, que SAP omite si la "
        "consulta usa $select). Usar ccwr_search para contratos de servicio Cisco (soporte/"
        "warranty) y ccw_order_status para el estado de órdenes de compra Cisco — son dos "
        "APIs de Cisco distintas, no intercambiables."
    ),
    stateless_http=True,
    # El servidor se expone detrás de una Route/Service de OKD con hostnames
    # reales (servicios-mcp.hermes.svc.cluster.local, servicios-mcp.trans.com.ar),
    # nunca "127.0.0.1"/"localhost" — por default el SDK solo permite esos dos
    # y rechaza cualquier otro Host header con "421 Invalid Host header".
    # En vez de deshabilitar la protección entera, se restringe explícitamente
    # a los hostnames reales de este servidor (capa adicional, redundante con
    # BearerAuthMiddleware pero de costo cero — sigue endureciendo contra un
    # ataque de DNS-rebinding real).
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[
            "servicios-mcp.trans.com.ar",
            "servicios-mcp.trans.com.ar:*",
            "servicios-mcp.hermes.svc.cluster.local",
            "servicios-mcp.hermes.svc.cluster.local:*",
            "localhost:*",
            "127.0.0.1:*",
        ],
        allowed_origins=[],
    ),
)


@mcp_server.tool()
def sap_query(
    entity: str,
    select: str | None = None,
    filter: str | None = None,
    orderby: str | None = None,
    top: int = 50,
    skip: int = 0,
) -> str:
    """Consulta de solo lectura (GET) contra una colección de SAP Business One
    Service Layer (OData 3.0). Ejemplos de `entity`: "Orders", "DeliveryNotes",
    "PurchaseOrders", "PurchaseDeliveryNotes", "BusinessPartners", "Items".
    `filter` usa sintaxis OData (ej: "DocDate ge '2026-01-01' and DocumentStatus eq 'bost_Open'").
    `select` es una lista de campos separados por coma. `top` tiene un tope de 1000 filas
    por llamada — para traer más, paginar con `skip`. Devuelve el JSON crudo de SAP
    (incluye "value": [...] y, si hay más páginas, "odata.nextLink").
    """
    _audit_tool_call("sap_query", entity=entity, filter=filter, top=top, skip=skip)
    try:
        data = sap.query(entity, select, filter, orderby, top, skip)
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps(data, ensure_ascii=False)


@mcp_server.tool()
def sap_get_entity(entity: str, entry_id: str) -> str:
    """Trae el detalle COMPLETO de un único documento de SAP por su clave primaria
    (normalmente DocEntry). A diferencia de sap_query, esto NO usa $select — por eso
    es la única forma de traer sub-colecciones anidadas que SAP omite en consultas
    con $select, como SerialNumbers dentro de DocumentLines. Ejemplo:
    sap_get_entity("DeliveryNotes", "3134").
    """
    _audit_tool_call("sap_get_entity", entity=entity, entry_id=entry_id)
    try:
        data = sap.get_entity(entity, entry_id)
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps(data, ensure_ascii=False)


@mcp_server.tool()
def ccwr_search(
    serial_numbers: list[str] | None = None,
    contract_numbers: list[str] | None = None,
    instance_numbers: list[str] | None = None,
    limit: int = 100,
    offset: int = 0,
) -> str:
    """Busca contratos de servicio de Cisco (CCWR — Contract/Warranty) por número de
    serie, número de contrato, o número de instancia. Pasar al menos una de las tres
    listas. Devuelve el JSON crudo de la API de Cisco. Útil para saber si un equipo
    tiene contrato de soporte activo y su vigencia.
    """
    _audit_tool_call(
        "ccwr_search",
        serial_numbers=serial_numbers,
        contract_numbers=contract_numbers,
        instance_numbers=instance_numbers,
    )
    if not (serial_numbers or contract_numbers or instance_numbers):
        return json.dumps({"error": "hay que pasar al menos una lista no vacía"})
    try:
        data = ccwr.search(serial_numbers, contract_numbers, instance_numbers, limit, offset)
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps(data, ensure_ascii=False)


@mcp_server.tool()
def ccw_order_status(
    order_search_key: str,
    order_search_value: str,
    page: int = 1,
    page_size: int = 5,
) -> str:
    """Consulta el estado de una orden de compra/venta de Cisco (CCW — Commerce
    GraphQL API). `order_search_key` es uno de los valores del enum de Cisco:
    "SALES_ORDER_ID" (número de Sales Order), "PURCHASE_ORDER_ID" (número de PO),
    "WEB_ORDER_ID", "DEAL_ID", "END_CUSTOMER_NAME", entre ~40 valores posibles.
    `order_search_value` es el identificador a buscar (por ejemplo el número de
    SO o de PO). Devuelve estado de la orden, referencia de PO del comprador,
    líneas (SKU, descripción, cantidad, estado) y detalle de precio. Un
    resultado vacío ("objects": []) con mensaje EXTNXG901 significa que la
    cuenta no tiene acceso a ESA orden puntual, no que la orden no exista.
    Distinto de ccwr_search: esto es estado de ÓRDENES, no de contratos.
    """
    _audit_tool_call(
        "ccw_order_status", order_search_key=order_search_key, order_search_value=order_search_value
    )
    try:
        data = ccw.get_order_details(order_search_key, order_search_value, page, page_size)
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps(data, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Auth middleware — bearer token simple, se aplica antes de llegar al ASGI de FastMCP
# ---------------------------------------------------------------------------


class BearerAuthMiddleware(BaseHTTPMiddleware):
    # Rutas del Authorization Server OAuth2 (RFC 8414/9728/7591) y del login
    # propio de /oauth/login: deben quedar alcanzables SIN un Bearer token
    # todavía — son justamente el mecanismo para obtenerlo. Siguen detrás de
    # la whitelist de IP de la Route, no es una superficie nueva a nivel red.
    _OAUTH_PUBLIC_PATHS = {"/authorize", "/token", "/register"}
    _OAUTH_PUBLIC_PREFIXES = ("/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource", "/oauth/login")

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in ("/healthz",):
            return await call_next(request)
        client_ip = request.client.host if request.client else "?"

        if path == "/admin" or path.startswith("/admin/"):
            return await self._dispatch_admin(request, call_next, client_ip)

        if path in self._OAUTH_PUBLIC_PATHS or path.startswith(self._OAUTH_PUBLIC_PREFIXES):
            return await call_next(request)

        auth = request.headers.get("authorization", "")
        challenge = {"WWW-Authenticate": f'Bearer resource_metadata="{RESOURCE_METADATA_URL}"'}
        if not auth.startswith("Bearer "):
            _audit_auth_fail("sin-token", client_ip, path)
            return JSONResponse(
                {"error": "falta Authorization: Bearer <token>"}, status_code=401, headers=challenge
            )
        token = auth[len("Bearer "):].strip()
        label = token_store.check(token)
        if not label:
            _audit_auth_fail("token-invalido", client_ip, path)
            return JSONResponse({"error": "token inválido"}, status_code=401, headers=challenge)
        request.state.token_label = label
        # Auditoría: quién (etiqueta del token) pega qué endpoint y desde
        # dónde, en cada request autenticado — visible con `oc logs`.
        log.info("AUTH_OK label=%s ip=%s path=%s", label, client_ip, path)
        label_ctx = current_token_label.set(label)
        ip_ctx = current_client_ip.set(client_ip)
        try:
            return await call_next(request)
        finally:
            current_token_label.reset(label_ctx)
            current_client_ip.reset(ip_ctx)

    @staticmethod
    async def _dispatch_admin(request: Request, call_next, client_ip: str):
        # El panel /admin usa Basic Auth (usuario/password propios, distintos
        # de los tokens Bearer del MCP) — hereda igual la whitelist de IP y el
        # TLS de la Route, no es una superficie nueva a nivel de red.
        auth = request.headers.get("authorization", "")
        challenge = {"WWW-Authenticate": 'Basic realm="servicios-mcp admin"'}
        if not auth.startswith("Basic "):
            return Response(status_code=401, headers=challenge)
        try:
            decoded = base64.b64decode(auth[len("Basic "):]).decode()
            user, _, password = decoded.partition(":")
        except Exception:
            return Response(status_code=401, headers=challenge)
        valid = secrets.compare_digest(user, ADMIN_USER) and secrets.compare_digest(
            password, ADMIN_PASSWORD
        )
        if not valid:
            log.warning("ADMIN_AUTH_FAIL ip=%s path=%s", client_ip, request.url.path)
            return Response(status_code=401, headers=challenge)
        log.info("ADMIN_AUTH_OK ip=%s path=%s method=%s", client_ip, request.url.path, request.method)
        return await call_next(request)


async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# Panel /admin — gestión de tokens de acceso, sin redeploy
# ---------------------------------------------------------------------------

ADMIN_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>servicios-mcp — tokens</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 900px;
         margin: 2rem auto; padding: 0 1rem; line-height: 1.4; }
  h1 { font-size: 1.3rem; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  th, td { text-align: left; padding: 0.5rem 0.6rem; border-bottom: 1px solid #8883; }
  th { font-size: 0.8rem; text-transform: uppercase; opacity: 0.7; }
  code { font-size: 0.85em; word-break: break-all; }
  button { cursor: pointer; padding: 0.3rem 0.7rem; border-radius: 6px; border: 1px solid #8886; background: transparent; }
  button.danger { border-color: #c33; color: #c33; }
  .row { display: flex; gap: 0.5rem; align-items: center; margin: 1rem 0; }
  input[type=text] { flex: 1; padding: 0.4rem 0.6rem; border-radius: 6px; border: 1px solid #8886; }
  .muted { opacity: 0.65; font-size: 0.85em; }
  .newtoken { background: #2a82; border: 1px solid #2a8; padding: 0.7rem 1rem; border-radius: 8px; margin: 1rem 0; }
  .newtoken code { font-size: 1rem; }
  h2 { font-size: 1.05rem; margin-top: 2.5rem; }
  .params { font-size: 0.8em; opacity: 0.8; max-width: 320px; overflow-wrap: anywhere; }
  .badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 999px; font-size: 0.75em; }
  .badge.tool_call { background: #2a83; }
  .badge.auth_fail { background: #c333; }
  .badge.oauth_login { background: #a3a3; }
  .toolbar { display: flex; justify-content: space-between; align-items: center; }
</style>
</head>
<body>
<h1>servicios-mcp — tokens de acceso</h1>
<p class="muted">SAP + CCWR (contratos) + CCW (órdenes) — solo lectura.</p>

<div class="row">
  <input type="text" id="label" placeholder="Nombre de la persona (etiqueta)">
  <button id="add">+ Generar token</button>
</div>
<div id="newtoken"></div>

<table id="tbl">
  <thead><tr>
    <th>Etiqueta</th><th>Token</th><th>Creado</th><th>Último uso</th><th>Llamadas</th><th></th>
  </tr></thead>
  <tbody></tbody>
</table>

<div class="toolbar">
  <h2>Registro de auditoría</h2>
  <button id="refresh-audit">↻ actualizar</button>
</div>
<p class="muted">Últimos eventos: llamadas a tools y autenticaciones fallidas. No se poda solo — el archivo completo queda en el servidor.</p>
<table id="audit-tbl">
  <thead><tr>
    <th>Fecha</th><th>Evento</th><th>Etiqueta / motivo</th><th>Tool</th><th>Parámetros</th><th>IP</th>
  </tr></thead>
  <tbody></tbody>
</table>

<script>
async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(await res.text());
  return res.status === 204 ? null : res.json();
}

function fmt(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('es-AR');
}

function mask(tok) {
  return tok.slice(0, 8) + '…' + tok.slice(-4);
}

async function load() {
  const items = await api('/admin/api/tokens');
  const tbody = document.querySelector('#tbl tbody');
  tbody.innerHTML = '';
  for (const t of items) {
    const tr = document.createElement('tr');
    const tokenId = 'tok-' + Math.random().toString(36).slice(2);
    tr.innerHTML = `
      <td>${t.label}</td>
      <td><code id="${tokenId}">${mask(t.token)}</code>
          <button data-full="${t.token}" class="reveal">mostrar</button>
          <button data-full="${t.token}" class="copy">copiar</button></td>
      <td>${fmt(t.created_at)}</td>
      <td>${fmt(t.last_used_at)}</td>
      <td>${t.call_count}</td>
      <td><button class="danger revoke" data-label="${t.label}">revocar</button></td>
    `;
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll('.reveal').forEach(b => b.onclick = () => {
    b.previousElementSibling.textContent = b.dataset.full;
  });
  tbody.querySelectorAll('.copy').forEach(b => b.onclick = () => {
    navigator.clipboard.writeText(b.dataset.full);
    b.textContent = 'copiado'; setTimeout(() => b.textContent = 'copiar', 1200);
  });
  tbody.querySelectorAll('.revoke').forEach(b => b.onclick = async () => {
    if (!confirm(`¿Revocar el token de "${b.dataset.label}"? No se puede deshacer.`)) return;
    await api('/admin/api/tokens/' + encodeURIComponent(b.dataset.label), { method: 'DELETE' });
    load();
  });
}

async function loadAudit() {
  const items = await api('/admin/api/audit?limit=200');
  const tbody = document.querySelector('#audit-tbl tbody');
  tbody.innerHTML = '';
  for (const e of items) {
    const tr = document.createElement('tr');
    const label = e.event === 'auth_fail' ? e.reason : e.label;
    const params = e.params ? JSON.stringify(e.params) : '';
    tr.innerHTML = `
      <td>${fmt(e.ts)}</td>
      <td><span class="badge ${e.event}">${e.event}</span></td>
      <td>${label ?? ''}</td>
      <td>${e.tool ?? e.client_name ?? '—'}</td>
      <td class="params">${params.length > 200 ? params.slice(0, 200) + '…' : params}</td>
      <td>${e.ip ?? '—'}</td>
    `;
    tbody.appendChild(tr);
  }
}
document.querySelector('#refresh-audit').onclick = loadAudit;

document.querySelector('#add').onclick = async () => {
  const label = document.querySelector('#label').value.trim();
  if (!label) { alert('Poné un nombre/etiqueta primero'); return; }
  const created = await api('/admin/api/tokens', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ label }),
  });
  document.querySelector('#newtoken').innerHTML = `
    <div class="newtoken">
      Token para <b>${created.label}</b> (copialo ahora, se puede volver a ver acá pero
      no hace falta guardarlo aparte):<br>
      <code>${created.token}</code>
    </div>`;
  document.querySelector('#label').value = '';
  load();
};

load();
loadAudit();
</script>
</body>
</html>"""


async def admin_page(request: Request) -> HTMLResponse:
    return HTMLResponse(ADMIN_HTML)


async def admin_list_tokens(request: Request) -> JSONResponse:
    return JSONResponse(token_store.list())


async def admin_create_token(request: Request) -> JSONResponse:
    body = await request.json()
    label = str(body.get("label", "")).strip()
    if not label:
        return JSONResponse({"error": "falta 'label'"}, status_code=400)
    token = token_store.add(label)
    log.info("ADMIN_TOKEN_CREATED label=%s", label)
    for info in token_store.list():
        if info["token"] == token:
            return JSONResponse({"token": token, **{k: v for k, v in info.items() if k != "token"}})
    return JSONResponse({"token": token, "label": label})


async def admin_revoke_token(request: Request) -> Response:
    label = request.path_params["label"]
    deleted = token_store.revoke(label)
    log.info("ADMIN_TOKEN_REVOKED label=%s eliminados=%d", label, deleted)
    if not deleted:
        return JSONResponse({"error": "no existe ningún token con esa etiqueta"}, status_code=404)
    return Response(status_code=204)


async def admin_list_audit(request: Request) -> JSONResponse:
    try:
        limit = int(request.query_params.get("limit", "200"))
    except ValueError:
        limit = 200
    return JSONResponse(audit_log.list(limit))


# ---------------------------------------------------------------------------
# /oauth/login — paso de "consentimiento" del flujo OAuth2. No crea usuarios
# ni contraseñas nuevas: pide el mismo token personal de servicios-mcp que
# ya usa Claude Code, lo valida contra TokenStore, y si es válido emite el
# authorization code que el SDK necesita para completar el intercambio.
# ---------------------------------------------------------------------------

_OAUTH_LOGIN_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>servicios-mcp — autorizar</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 420px;
         margin: 3rem auto; padding: 0 1rem; line-height: 1.5; }}
  h1 {{ font-size: 1.15rem; }}
  p.muted {{ opacity: 0.7; font-size: 0.9em; }}
  input[type=password] {{ width: 100%; padding: 0.6rem 0.7rem; border-radius: 6px;
         border: 1px solid #8886; box-sizing: border-box; font-size: 1rem; margin: 0.5rem 0 1rem; }}
  button {{ width: 100%; padding: 0.6rem; border-radius: 6px; border: none;
         background: #2a6df4; color: white; font-size: 1rem; cursor: pointer; }}
  .err {{ color: #c33; font-size: 0.9em; }}
</style>
</head>
<body>
<h1>Autorizar {client_name} en servicios-mcp</h1>
<p class="muted">Pegá tu token de acceso personal de servicios-mcp (el mismo que usás
con Claude Code) para conectar {client_name}. Esto NO crea una cuenta nueva —
solo confirma quién sos.</p>
{error}
<form method="post" action="/oauth/login">
  <input type="hidden" name="login_id" value="{login_id}">
  <input type="password" name="token" placeholder="tok_..." autofocus required>
  <button type="submit">Autorizar</button>
</form>
</body>
</html>"""


def _render_oauth_login(login_id: str, client_name: str, error: str = "") -> HTMLResponse:
    error_html = f'<p class="err">{error}</p>' if error else ""
    html = _OAUTH_LOGIN_HTML.format(
        client_name=client_name or "esta app", login_id=login_id, error=error_html
    )
    return HTMLResponse(html, status_code=401 if error else 200)


async def oauth_login_get(request: Request) -> Response:
    login_id = request.query_params.get("login_id", "")
    pending = oauth_provider.peek_pending_login(login_id)
    if not pending:
        return HTMLResponse(
            "<h1>Enlace inválido o vencido</h1><p>Volvé a intentar agregar el conector desde Claude.</p>",
            status_code=400,
        )
    client, _params = pending
    return _render_oauth_login(login_id, client.client_name or client.client_id)


async def oauth_login_post(request: Request) -> Response:
    form = await request.form()
    login_id = str(form.get("login_id", ""))
    token = str(form.get("token", "")).strip()
    client_ip = request.client.host if request.client else "?"

    pending = oauth_provider.peek_pending_login(login_id)
    if not pending:
        return HTMLResponse(
            "<h1>Enlace inválido o vencido</h1><p>Volvé a intentar agregar el conector desde Claude.</p>",
            status_code=400,
        )
    client, params = pending

    label = token_store.check(token) if token else None
    if not label:
        _audit_auth_fail("oauth-token-invalido", client_ip, "/oauth/login")
        return _render_oauth_login(
            login_id, client.client_name or client.client_id, error="Token inválido — probá de nuevo."
        )

    oauth_provider.consume_pending_login(login_id)
    code = oauth_provider.issue_code(client, params, personal_token=token, label=label)
    _audit_oauth_login(label, client_ip, client.client_id, client.client_name)

    redirect_url = construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)
    return RedirectResponse(redirect_url, status_code=302, headers={"Cache-Control": "no-store"})


@contextlib.asynccontextmanager
async def lifespan(app: Starlette) -> AsyncIterator[None]:
    async with mcp_server.session_manager.run():
        labels = [info["label"] for info in token_store.list()]
        log.info("hermes-mcp arrancado. Tokens configurados: %s", labels)
        yield


def build_app() -> Starlette:
    from starlette.routing import Mount, Route

    # Rutas del Authorization Server OAuth2 — generadas y validadas por el
    # SDK oficial de MCP (PKCE, expiración de código, auth de client_secret,
    # metadata RFC 8414/9728, DCR RFC 7591). Ver ServiciosMcpOAuthProvider
    # más arriba para la única parte propia (el login).
    oauth_routes = create_auth_routes(
        provider=oauth_provider,
        issuer_url=OAUTH_ISSUER_URL,
        client_registration_options=ClientRegistrationOptions(enabled=True),
        revocation_options=RevocationOptions(enabled=False),
    )
    protected_resource_routes = create_protected_resource_routes(
        resource_url=OAUTH_RESOURCE_URL,
        authorization_servers=[OAUTH_ISSUER_URL],
        resource_name="servicios-mcp",
    )

    app = Starlette(
        routes=[
            Route("/healthz", healthz),
            Route("/admin", admin_page, methods=["GET"]),
            Route("/admin/api/tokens", admin_list_tokens, methods=["GET"]),
            Route("/admin/api/tokens", admin_create_token, methods=["POST"]),
            Route("/admin/api/tokens/{label}", admin_revoke_token, methods=["DELETE"]),
            Route("/admin/api/audit", admin_list_audit, methods=["GET"]),
            Route("/oauth/login", oauth_login_get, methods=["GET"]),
            Route("/oauth/login", oauth_login_post, methods=["POST"]),
            *oauth_routes,
            *protected_resource_routes,
            Mount("/", app=mcp_server.streamable_http_app()),
        ],
        middleware=[Middleware(BearerAuthMiddleware)],
        lifespan=lifespan,
    )
    return app


app = build_app()

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
