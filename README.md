# hermes-mcp

Servidor MCP remoto (Streamable HTTP), de **solo lectura**, que expone la API
de SAP Business One Service Layer y la API de contratos de servicio de Cisco
(CCWR) usadas por el proyecto Hermes de Trans Industrias Electrónicas.

Pensado para que un cliente externo (otro Claude, en otra cuenta) pueda
agregarlo como conector MCP remoto y consultar los mismos datos sin acceso
directo al clúster ni a las credenciales reales de SAP/Cisco.

## Tools expuestas

- `sap_query(entity, select, filter, orderby, top, skip)` — `GET` genérico
  contra una colección OData de SAP B1 Service Layer (`Orders`,
  `DeliveryNotes`, `PurchaseOrders`, `PurchaseDeliveryNotes`,
  `BusinessPartners`, `Items`, etc.).
- `sap_get_entity(entity, entry_id)` — `GET` completo de un documento por
  clave primaria (necesario para sub-colecciones anidadas como
  `SerialNumbers`, que SAP omite si la consulta usa `$select`).
- `ccwr_search(serial_numbers, contract_numbers, instance_numbers, limit, offset)`
  — búsqueda de contratos de servicio de Cisco.

**Regla no negociable, heredada del skill `sap-service-layer` de Hermes:**
el servidor nunca arma un `POST`/`PATCH`/`DELETE` contra una entidad de
datos de SAP. Las únicas llamadas POST son `Login`/`Logout` de sesión SAP
y el token endpoint OAuth2 de Cisco.

## Autenticación

`Authorization: Bearer <token>` en cada request. Los tokens válidos se
configuran vía la variable de entorno `MCP_ACCESS_TOKENS`
(`token1:etiqueta1,token2:etiqueta2,...`) — cada persona tiene su propio
token, independiente de las credenciales reales de SAP/Cisco, así que se
puede revocar el acceso de una persona sin tocar nada más.

## Variables de entorno

| Variable | Requerida | Descripción |
|---|---|---|
| `SAP_SL_COMPANY_DB` | Sí | Base de datos de SAP B1 |
| `SAP_SL_USERNAME` | Sí | Usuario SAP B1 |
| `SAP_SL_PASSWORD` | Sí | Password SAP B1 |
| `SAP_BASE_URL` | No (default `https://sap.trans.com.ar:50000/b1s/v1`) | Base de la Service Layer |
| `CCWR_CLIENT_ID` | Sí (si se usa `ccwr_search`) | Client ID OAuth2 Cisco |
| `CCWR_CLIENT_SECRET` | Sí (si se usa `ccwr_search`) | Client Secret OAuth2 Cisco |
| `CCWR_TOKEN_URL` | No (default `https://id.cisco.com/oauth2/default/v1/token`) | Token endpoint |
| `CCWR_API_URL` | No (default `.../ccw/renewals/api/v1.0/search/lines`) | Endpoint de búsqueda |
| `MCP_ACCESS_TOKENS` | Sí | Tokens de acceso al MCP, ver arriba |
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

Pensado para correr como Deployment propio en OKD (namespace `hermes`),
detrás de una Route pública con TLS, mismo patrón que el resto de los
componentes de Hermes en este proyecto (`hermes-agent`, `honcho-api`,
`trilium`). Ver el changelog del proyecto Hermes (doc interno, no en este
repo) para el detalle de despliegue real.
