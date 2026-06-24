
# ==================== Builder Stage ====================
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build \
    qtbase5-dev qttools5-dev-tools \
    libssl-dev pkg-config \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN mkdir -p build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release \
          -G Ninja \
          -DCMAKE_INSTALL_PREFIX=/usr/local \
          .. && \
    ninja && \
    ninja install

# ==================== Runtime Stage ====================
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    QT_QPA_PLATFORM=xcb \
    LANG=C.UTF-8

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    libqt5widgets5 libqt5gui5 libqt5core5a \
    libssl3 libgl1 libx11-6 libxcb1 \
    libxkbcommon-x11-0 libfontconfig1 \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && apt-get clean

# Копируем приложение
COPY --from=builder /usr/local/bin/DigitalSigner /usr/bin/DigitalSigner

WORKDIR /data

ENTRYPOINT ["/usr/bin/DigitalSigner"]