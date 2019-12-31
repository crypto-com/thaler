FROM rust:1.39.0 AS builder
LABEL maintainer="calvin@crypto.com"

ARG CHAIN_ABCI_FEATURES
ARG CLIENT_FEATURES

ENV RUSTFLAGS "-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"

RUN apt-get update -y && \
    apt-get install cmake libgflags-dev libzmq3-dev pkg-config clang -y

COPY . .

RUN cargo build --bin dev-utils
RUN cd chain-abci && cargo build --features "${CHAIN_ABCI_FEATURES}"
RUN cd client-cli && cargo build --features "${CLIENT_FEATURES}"
RUN cd client-rpc && cargo build --features "${CLIENT_FEATURES}"
RUN mkdir -p /output/bin && \
    for bin in chain-abci client-cli client-rpc dev-utils; do mv "target/debug/${bin}" /output/bin/; done && \
    mv docker/wait-for-it.sh /output/bin/


FROM debian:buster

RUN apt-get update -y && \
    apt-get install --no-install-recommends libssl-dev libzmq3-dev -y && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /output/bin/. /usr/bin/

STOPSIGNAL SIGTERM
