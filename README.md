# servicios-mcp

Servidor MCP remoto (Streamable HTTP), de **SOLO CONSULTA** (nunca escribe
ni modifica nada en SAP ni en Cisco), que expone la API de SAP Business One
Service Layer, la API de contratos de servicio de Cisco (CCWR) y la API de
estado de órdenes de Cisco (CCW) usadas por el proyecto Hermes de Trans
Industrias Electrónicas.

Pensado para que un cliente externo (otro Claude, en otra cuenta) pueda
agregarlo como conector MCP remoto y consultar los mismos datos sin acceso
directo al clúster ni a las credenciales reales de SAP/Cisco.

## Tools expuestas

**Las cuatro tools son exclusivamente de lectura — no existe en este código
ninguna tool que pueda crear, modificar o borrar nada en SAP, CCWR ni CCW.**

- `sap_query(entity, select, filter, orderby, top, skip)` — `GET` genérico
  contra una colección OData de SAP B1 Service Layer (`Orders`,
  `DeliveryNotes`, `PurchaseOrders`, `PurchaseDeliveryNotes`,
  `BusinessPartners`, `Items`, etc.).
- `sap_get_entity(entity, entry_id)` — `GET` completo de un documento por
  clave primaria (necesario para sub-colecciones anidadas como
  `SerialNumbers`, que SAP omite si la consulta usa `$select`).
- `ccwr_search(serial_numbers, contract_numbers, instance_numbers, limit, offset)`
  — búsqueda de **contratos** de servicio de Cisco (soporte/warranty, API
  CCWR — legacy).
- `ccw_order_status(order_search_key, order_search_value, page, page_size)`
  — estado de **órdenes** de compra/venta de Cisco (API CCW — Commerce
  GraphQL). Distinto de `ccwr_search`: contratos y órdenes son dos APIs de
  Cisco separadas, con credenciales propias cada una.

**Regla no negociable, heredada de los skills `sap-service-layer`,
`ccwr-contract-admin` y `order-status` de Hermes:** el servidor nunca arma
un `POST`/`PATCH`/`DELETE` contra una entidad de datos de SAP, CCWR o CCW.
Las únicas llamadas POST del código son `Login`/`Logout` de sesión SAP y
los token endpoints OAuth2 de Cisco — todas de autenticación, ninguna de
datos.

## Autenticación

`Authorization: Bearer <token>` en cada request. Los tokens se gestionan
desde el panel web `/admin` (ver abajo) — cada persona tiene su propio
token, independiente de las credenciales reales de SAP/Cisco, así que se
puede revocar el acceso de una persona sin tocar nada más ni redeployar.

## Panel `/admin` — gestión de tokens

`GET /admin` sirve una página HTML+JS (sin dependencias nuevas) protegida
con HTTP Basic Auth (`ADMIN_USER`/`ADMIN_PASSWORD`) para generar y revocar
tokens de acceso en caliente. Los tokens se persisten en
`TOKENS_FILE` (default `/data/tokens.json`, pensado para montarse sobre un
PVC) — en el primer arranque sobre un archivo inexistente, se siembran
automáticamente desde la variable de entorno legacy `MCP_ACCESS_TOKENS`
(`token1:etiqueta1,token2:etiqueta2,...`), que de ahí en más queda sin
efecto real. API REST detrás del mismo Basic Auth:
`GET /admin/api/tokens` (listar), `POST /admin/api/tokens`
(`{"label": "..."}` → crea y devuelve el token), `DELETE
/admin/api/tokens/{label}` (revoca).

## Variables de entorno

| Variable | Requerida | Descripción |
|---|---|---|
| `SAP_SL_COMPANY_DB` | Sí | Base de datos de SAP B1 |
| `SAP_SL_USERNAME` | Sí | Usuario SAP B1 |
| `SAP_SL_PASSWORD` | Sí | Password SAP B1 |
| `SAP_BASE_URL` | No (default `https://sap.trans.com.ar:50000/b1s/v1`) | Base de la Service Layer |
| `CCWR_CLIENT_ID` | Sí (si se usa `ccwr_search`) | Client ID OAuth2 Cisco (contratos) |
| `CCWR_CLIENT_SECRET` | Sí (si se usa `ccwr_search`) | Client Secret OAuth2 Cisco (contratos) |
| `CCWR_TOKEN_URL` | No (default `https://id.cisco.com/oauth2/default/v1/token`) | Token endpoint CCWR |
| `CCWR_API_URL` | No (default `.../ccw/renewals/api/v1.0/search/lines`) | Endpoint de búsqueda CCWR |
| `CCW_CLIENT_ID` | Sí (si se usa `ccw_order_status`) | Client ID OAuth2 Cisco (órdenes) |
| `CCW_CLIENT_SECRET` | Sí (si se usa `ccw_order_status`) | Client Secret OAuth2 Cisco (órdenes) |
| `CCW_TOKEN_URL` | No (default `https://id.cisco.com/oauth2/default/v1/token`) | Token endpoint CCW |
| `CCW_API_URL` | No (default `https://capi.cisco.com/commerce/apis`) | Endpoint GraphQL CCW |
| `MCP_ACCESS_TOKENS` | No | Solo usado para sembrar `TOKENS_FILE` en el primer arranque, ver "Panel /admin" |
| `TOKENS_FILE` | No (default `/data/tokens.json`) | Store persistente de tokens, gestionado desde `/admin` |
| `ADMIN_USER` | Sí | Usuario del panel `/admin` |
| `ADMIN_PASSWORD` | Sí | Password del panel `/admin` |
| `PORT` | No (default `8080`) | Puerto HTTP |

## Correr local

```bash
pip install -r requirements.txt
SAP_SL_COMPANY_DB=... SAP_SL_USERNAME=... SAP_SL_PASSWORD=... \
MCP_ACCESS_TOKENS="tok_ejemplo:mi-token" \
python3 src/server.py
```

Healthcheck sin auth: `GET /healthz`. Endpoint MCP: `POST /mcp`.

## Despliegue

Corre como Deployment propio en OKD (namespace `hermes`, componente
`servicios-mcp` — renombrado desde `hermes-mcp` el 2026-08-14), detrás de
una Route pública (`servicios-mcp.trans.com.ar`) con TLS real, mismo patrón
que el resto de los componentes de Hermes en este proyecto (`hermes-agent`,
`honcho-api`, `trilium`). Ver el changelog del proyecto Hermes (doc
interno, no en este repo) para el detalle de despliegue real.
