FROM python:3.13-slim

WORKDIR /app

COPY . /app

RUN pip install --upgrade pip \
    && pip install uv \
    && uv sync --frozen --no-dev

EXPOSE 8000

CMD ["/app/.venv/bin/python", "-m", "mcp_redmine.server", "--transport", "streamable-http"]
