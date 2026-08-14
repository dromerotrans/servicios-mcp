FROM python:3.12-slim

# Corre sin privilegios, sin escalar UID — pensado para la SCC default
# restricted-v2 de OKD (mismo patrón que honcho-api/honcho-deriver en
# este proyecto: HOME fijo, sin necesidad de root).
ENV HOME=/app \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/server.py .

# UID arbitrario asignado por OKD en tiempo de ejecución (restricted-v2) —
# el directorio de trabajo tiene que ser escribible por el grupo raíz.
RUN chgrp -R 0 /app && chmod -R g=u /app

EXPOSE 8080

CMD ["python3", "server.py"]
