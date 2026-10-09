FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    VIRTUAL_ENV=/opt/icc610/venv \
    ICC610_TOOLS_DIR=/opt/icc610/.tools \
    ICC610_GRYPE_SEED_DIR=/opt/icc610/grype-seed \
    PATH=/opt/icc610/venv/bin:/opt/icc610/.tools/node/bin:$PATH

# Estos paquetes viven en la imagen; no se usa Python, Git, Node ni escáneres del anfitrión.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl git xz-utils python3.14 python3.14-venv python3.14-tk \
       libtcl8.6 libtk8.6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/icc610
COPY requirements-lock.txt ./
RUN python3.14 -m venv "$VIRTUAL_ENV" \
    && python -m pip install --no-cache-dir -r requirements-lock.txt

# Instala herramientas verificadas antes de copiar el código para reutilizar las capas.
COPY support/__init__.py ./support/
COPY support/scripts/install_codeql.py support/scripts/install_scanners.py support/scripts/install_node.py support/scripts/install_tkinter.py ./support/scripts/
COPY support/interface/__init__.py support/interface/tk_runtime.py ./support/interface/
RUN python support/scripts/install_codeql.py
RUN python support/scripts/install_scanners.py
RUN python support/scripts/install_node.py
RUN apt-get update \
    && python support/scripts/install_tkinter.py \
    && rm -rf /var/lib/apt/lists/*

# La imagen incluye una base inicial válida. El punto de entrada la copia al
# espacio montado para compartirla entre futuras ejecuciones y contenedores.
RUN mkdir -p "$ICC610_GRYPE_SEED_DIR" \
    && GRYPE_DB_CACHE_DIR="$ICC610_GRYPE_SEED_DIR" .tools/grype/grype db update \
    && GRYPE_DB_CACHE_DIR="$ICC610_GRYPE_SEED_DIR" .tools/grype/grype db status -o json

WORKDIR /workspace
COPY . .
COPY support/scripts/docker_entrypoint.py /usr/local/bin/icc610-entrypoint.py
RUN chown -R 1000:1000 /workspace
USER 1000:1000

ENTRYPOINT ["python", "/usr/local/bin/icc610-entrypoint.py"]
CMD ["python", "main.py", "--no-gui"]
