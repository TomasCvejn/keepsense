FROM registry.access.redhat.com/ubi9/python-312-minimal

COPY --from=ghcr.io/astral-sh/uv:0.13.4 /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-cache

COPY keepsense ./keepsense

EXPOSE 8000
CMD [".venv/bin/fastapi", "run", "keepsense/main.py"]
