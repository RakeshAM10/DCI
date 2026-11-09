# SCI server image. Build: docker build -t sci-server .   Run: see deploy/docker-compose.yml
FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml constraints.txt README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install -c constraints.txt ".[server]"

FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin sci && mkdir /data && chown sci /data
COPY --from=build /install /usr/local
USER sci
ENV SCI_DATA_DIR=/data SCI_HOST=0.0.0.0 SCI_PORT=8080 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('SCI_PORT','8080')+'/healthz',timeout=4)"
ENTRYPOINT ["sci-server"]
CMD ["run"]
