FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install --no-cache-dir . \
    && useradd --create-home --home-dir /home/aiegis --shell /usr/sbin/nologin aiegis \
    && mkdir -p /var/lib/aiegis /etc/aiegis \
    && chown -R aiegis:aiegis /var/lib/aiegis /home/aiegis

USER aiegis

VOLUME ["/var/lib/aiegis"]

ENTRYPOINT ["aiegis"]
CMD ["mcp-stdio"]
