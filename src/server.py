"""
hermes-mcp — servidor MCP remoto (Streamable HTTP) que expone, de solo
lectura, la API de SAP Business One Service Layer y la API de contratos
de Cisco (CCWR) usadas por Hermes.

Diseñado para correr como un Deployment propio en el namespace `hermes`
de OKD, detrás de una Route pública con TLS, para que un cliente externo
(otro Claude, en otra cuenta) pueda agregarlo como conector MCP remoto y
consultar los mismos datos sin tener acceso directo a las credenciales
reales de SAP/Cisco ni al clúster.

Autenticación: bearer token simple (`Authorization: Bearer <token>`),
verificado contra una lista de tokens válidos cargada desde la variable
de entorno MCP_ACCESS_TOKENS (formato "token1:etiqueta1,token2:etiqueta2").
Cada token es independiente de las credenciales reales de SAP/Cisco —
se puede revocar sin tocar nada más.

Reglas heredadas del skill sap-service-layer de Hermes (no negociables):
SOLO LECTURA contra SAP. El servidor nunca arma un POST/PATCH/DELETE
contra una entidad de datos — las únicas llamadas POST son Login/Logout
de sesión SAP y el token endpoint OAuth2 de Cisco.
"""

import contextlib
import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
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

# "token1:etiqueta1,token2:etiqueta2" -> {"token1": "etiqueta1", ...}
_raw_tokens = os.environ.get("MCP_ACCESS_TOKENS", "")
VALID_TOKENS: dict[str, str] = {}
for pair in _raw_tokens.split(","):
    pair = pair.strip()
    if not pair:
        continue
    if ":" in pair:
        tok, label = pair.split(":", 1)
    else:
        tok, label = pair, "sin-etiqueta"
    VALID_TOKENS[tok.strip()] = label.strip()

if not VALID_TOKENS:
    raise RuntimeError(
        "MCP_ACCESS_TOKENS vacío — el servidor no puede arrancar sin al menos un token "
        "de acceso configurado (evita quedar abierto sin auth por error de despliegue)."
    )

MAX_TOP = 1000  # tope duro, evita que un $top gigante tire abajo el server o SAP


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


sap = SapClient()
ccwr = CcwrClient()


# ---------------------------------------------------------------------------
# Servidor MCP y tools
# ---------------------------------------------------------------------------

mcp_server = FastMCP(
    name="hermes-sap-ccwr",
    instructions=(
        "Herramientas de SOLO LECTURA contra SAP Business One (Service Layer) y la API de "
        "contratos de servicio de Cisco (CCWR) de Trans Industrias. Nunca hay escritura: "
        "sap_query/sap_get_entity solo arman GET; no existe ninguna tool de creación, "
        "modificación o borrado. Usar sap_query para listar/filtrar documentos (Orders, "
        "DeliveryNotes, PurchaseOrders, PurchaseDeliveryNotes, BusinessPartners, etc. — "
        "ver la doc de entidades OData de SAP B1 Service Layer) y sap_get_entity cuando se "
        "necesite el detalle completo de UN documento puntual (por ejemplo para traer "
        "SerialNumbers, que SAP omite si la consulta usa $select)."
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
    if not (serial_numbers or contract_numbers or instance_numbers):
        return json.dumps({"error": "hay que pasar al menos una lista no vacía"})
    try:
        data = ccwr.search(serial_numbers, contract_numbers, instance_numbers, limit, offset)
    except Exception as e:
        return json.dumps({"error": str(e)})
    return json.dumps(data, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Auth middleware — bearer token simple, se aplica antes de llegar al ASGI de FastMCP
# ---------------------------------------------------------------------------


class BearerAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in ("/healthz",):
            return await call_next(request)
        client_ip = request.client.host if request.client else "?"
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            log.warning("AUTH_FAIL sin-token ip=%s path=%s", client_ip, request.url.path)
            return JSONResponse({"error": "falta Authorization: Bearer <token>"}, status_code=401)
        token = auth[len("Bearer "):].strip()
        label = VALID_TOKENS.get(token)
        if not label:
            log.warning("AUTH_FAIL token-invalido ip=%s path=%s", client_ip, request.url.path)
            return JSONResponse({"error": "token inválido"}, status_code=401)
        request.state.token_label = label
        # Auditoría: quién (etiqueta del token) pega qué endpoint y desde
        # dónde, en cada request autenticado — visible con `oc logs`.
        log.info("AUTH_OK label=%s ip=%s path=%s", label, client_ip, request.url.path)
        return await call_next(request)


async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


@contextlib.asynccontextmanager
async def lifespan(app: Starlette) -> AsyncIterator[None]:
    async with mcp_server.session_manager.run():
        log.info("hermes-mcp arrancado. Tokens configurados: %s", list(VALID_TOKENS.values()))
        yield


def build_app() -> Starlette:
    from starlette.routing import Mount, Route

    app = Starlette(
        routes=[
            Route("/healthz", healthz),
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
