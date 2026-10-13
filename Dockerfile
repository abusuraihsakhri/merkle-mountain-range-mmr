FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY . .
RUN python -m pip install --no-cache-dir ".[api]" \
    && useradd --system --create-home --shell /usr/sbin/nologin appuser
USER appuser
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/health', timeout=4).read()"

CMD ["python", "cli.py", "serve", "--host", "0.0.0.0", "--port", "8000"]
