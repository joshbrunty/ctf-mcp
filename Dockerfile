# CTF MCP — private remote team box (Phase 2)
# Prefer Tailscale / campus VLAN. Do not publish to the open internet without TLS + IdP.
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        file \
        binutils \
        bsdmainutils \
        unzip \
        p7zip-full \
        exiftool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY ctf_mcp ./ctf_mcp
COPY scripts ./scripts

RUN pip install --no-cache-dir -e .

ENV CTF_MCP_HOSTED=1 \
    CTF_MCP_TRANSPORT=streamable-http \
    CTF_MCP_HOST=0.0.0.0 \
    CTF_MCP_PORT=8765 \
    CTF_MCP_HTTP_PATH=/mcp \
    CTF_WORKSPACE=/data/workspaces \
    PYTHONUNBUFFERED=1

VOLUME ["/data/workspaces"]
EXPOSE 8765

# Auth token must be provided at runtime (compose .env).
CMD ["ctf-mcp", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8765"]
