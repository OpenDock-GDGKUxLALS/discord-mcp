FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
# Dependencies first, so that changing the source does not reinstall them.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev
ENV MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    MCP_DATA_DIR=/data
VOLUME /data
EXPOSE 8000
CMD ["/app/.venv/bin/discord-mcp"]
