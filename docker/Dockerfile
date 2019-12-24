# syntax = docker/dockerfile:experimental
FROM baiduxlab/sgx-rust:1804-1.1.0 as builder
LABEL maintainer="calvin@crypto.com"

RUN echo 'source /opt/sgxsdk/environment' >> /root/.docker_bashrc && \
    echo 'source /root/.cargo/env' >> /root/.docker_bashrc

RUN --mount=type=cache,target=/var/lib/apt apt-get update -y && \
    apt-get install cmake libgflags-dev libzmq3-dev pkg-config clang -y

ENV SGX_SDK /opt/sgxsdk
ENV PATH "/root/.cargo/bin:$PATH"
ENV PKG_CONFIG_PATH "$PKG_CONFIG_PATH:$SGX_SDK/pkgconfig"
ENV LD_LIBRARY_PATH "$SGX_SDK/sdk_libs"

ENV RUSTFLAGS "-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"
ENV CARGO_TARGET_DIR /target

ARG SGX_MODE=SW
ARG NETWORK_ID=AB

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/root/.cargo/advisory-db \
    --mount=type=cache,target=$CARGO_TARGET_DIR \
    --mount=type=bind,target=/src,source=.,rw \
    set -e; cd /src; \
    cargo build --no-default-features --features mesalock_sgx --manifest-path chain-abci/Cargo.toml; \
    cargo build --no-default-features --features mesalock_sgx --manifest-path chain-tx-enclave/tx-query/app/Cargo.toml; \
    cargo build --no-default-features --features mesalock_sgx --manifest-path chain-tx-enclave/tx-validation/app/Cargo.toml; \
    make -C ./chain-tx-enclave/tx-query SGX_DEBUG=1; \
    make -C ./chain-tx-enclave/tx-validation SGX_DEBUG=1; \
    cargo build -p client-cli -p client-rpc -p dev-utils; \
    cp /src/docker/wait-for-it.sh $CARGO_TARGET_DIR/debug

RUN mkdir /output && \
    for bin in chain-abci client-cli client-rpc dev-utils tx-validation-app tx-query-app tx_query_enclave.signed.so tx_validation_enclave.signed.so wait-for-it.sh; do mv "$CARGO_TARGET_DIR/debug/${bin}" /output; done

FROM debian:buster

RUN apt-get update -y && \
    apt-get install --no-install-recommends libssl-dev libzmq3-dev -y && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir /crypto-chain
WORKDIR /crypto-chain
ENV PATH "/crypto-chain:$PATH"
COPY --from=builder /output/. /crypto-chain
COPY --from=builder /opt/sgxsdk/lib64/*.so /usr/lib/x86_64-linux-gnu
COPY --from=builder /opt/intel/libsgx-enclave-common /opt/intel/libsgx-enclave-common
