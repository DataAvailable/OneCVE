FROM node:22-bookworm-slim AS web-builder

WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
ARG NEXT_PUBLIC_NSPA_API_URL=http://127.0.0.1:8000
ENV NEXT_PUBLIC_NSPA_API_URL=${NEXT_PUBLIC_NSPA_API_URL}
RUN npm run build


FROM ubuntu:24.04 AS svf-builder

ARG ONECVE_APT_MIRROR=
ENV DEBIAN_FRONTEND=noninteractive
RUN if [ -n "$ONECVE_APT_MIRROR" ]; then \
        sed -i \
            -e "s|http://archive.ubuntu.com/ubuntu|$ONECVE_APT_MIRROR|g" \
            -e "s|http://security.ubuntu.com/ubuntu|$ONECVE_APT_MIRROR|g" \
            /etc/apt/sources.list.d/ubuntu.sources; \
    fi \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        clang-18 \
        cmake \
        libffi-dev \
        libtinfo-dev \
        libxml2-dev \
        libz3-dev \
        llvm-18-dev \
        ninja-build \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY SVF/ /build/SVF/
RUN cmake -S /build/SVF -B /opt/svf -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DSVF_ENABLE_ASSERTIONS=ON \
        -DSVF_WARN_AS_ERROR=OFF \
        -DLLVM_DIR=/usr/lib/llvm-18/lib/cmake/llvm \
    && cmake --build /opt/svf --target saber -j2 \
    && test -x /opt/svf/bin/saber \
    && test -s /opt/svf/lib/extapi.bc


FROM ubuntu:24.04 AS runtime

ARG ONECVE_APT_MIRROR=
LABEL org.opencontainers.image.title="OneCVE" \
      org.opencontainers.image.description="Local OneCVE vulnerability scanner powered by SVF/Saber" \
      org.opencontainers.image.source="local-workspace"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NSPA_ROOT=/app \
    NSPA_WEB_DATA_DIR=/data \
    NSPA_SVF_BUILD_DIR=/opt/svf \
    NSPA_SABER=/opt/svf/bin/saber \
    SVF_EXTAPI=/opt/svf/lib/extapi.bc \
    NSPA_CLANG=clang-18 \
    NSPA_CLANGXX=clang++-18 \
    CC=clang-18 \
    CXX=clang++-18 \
    PATH=/opt/venv/bin:/opt/svf/bin:/usr/lib/llvm-18/bin:${PATH} \
    LD_LIBRARY_PATH=/usr/lib/llvm-18/lib

RUN if [ -n "$ONECVE_APT_MIRROR" ]; then \
        sed -i \
            -e "s|http://archive.ubuntu.com/ubuntu|$ONECVE_APT_MIRROR|g" \
            -e "s|http://security.ubuntu.com/ubuntu|$ONECVE_APT_MIRROR|g" \
            /etc/apt/sources.list.d/ubuntu.sources; \
    fi; \
    set -eu; \
    attempt=1; \
    until apt-get -o Acquire::Retries=5 update \
        && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
        autoconf \
        automake \
        bash \
        bear \
        bison \
        build-essential \
        ca-certificates \
        clang-18 \
        cmake \
        file \
        flex \
        git \
        gosu \
        libffi-dev \
        libevent-dev \
        libext2fs-dev \
        libncurses-dev \
        libfuse3-dev \
        libglib2.0-dev \
        libgpgme-dev \
        liblzma-dev \
        libreadline-dev \
        libssl-dev \
        libtinfo6 \
        libtool \
        libxml2 \
        libz3-4 \
        llvm-18 \
        llvm-18-dev \
        make \
        meson \
        ninja-build \
        pkg-config \
        python3 \
        python3-pip \
        python3-venv \
        tar \
        tini \
        unzip \
        xz-utils \
        zip \
        zlib1g-dev; \
    do \
        if [ "$attempt" -ge 5 ]; then exit 1; fi; \
        attempt=$((attempt + 1)); \
        rm -rf /var/lib/apt/lists/*; \
        sleep 5; \
    done; \
    rm -rf /var/lib/apt/lists/*; \
    python3 -m venv /opt/venv

WORKDIR /app
COPY requirements-web.txt /app/requirements-web.txt
RUN pip install --no-cache-dir -r /app/requirements-web.txt \
    && pip install --no-cache-dir tree-sitter tree-sitter-c tree-sitter-cpp

COPY --from=svf-builder /opt/svf /opt/svf
COPY --from=web-builder /usr/local/bin/node /usr/local/bin/node
COPY --from=web-builder --chown=10001:10001 /build/web /app/web
COPY nspa/ /app/nspa/
COPY docker/entrypoint.sh /app/docker/entrypoint.sh

RUN groupadd --gid 10001 onecve \
    && useradd --uid 10001 --gid 10001 --create-home --shell /bin/bash onecve \
    && mkdir -p /data /workspace \
    && chown -R onecve:onecve /data /workspace \
    && chmod 0755 /app/docker/entrypoint.sh \
    && test -s /etc/passwd \
    && test -s /etc/group \
    && getent passwd onecve >/dev/null \
    && getent group onecve >/dev/null

USER onecve

EXPOSE 3000 8000
VOLUME ["/data"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3); urllib.request.urlopen('http://127.0.0.1:3000', timeout=3)" || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/app/docker/entrypoint.sh"]
