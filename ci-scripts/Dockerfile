FROM baiduxlab/sgx-rust:1804-1.1.1
LABEL maintainer="Crypto.com"

ENV PATH=/root/.cargo/bin:/root/.local/bin:$PATH
ENV RUST_BACKTRACE=1
ENV RUSTFLAGS "-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"

RUN echo 'source /opt/sgxsdk/environment' >> /root/.docker_bashrc && \
    echo 'source /root/.cargo/env' >> /root/.docker_bashrc

RUN set -e; \
    rustup set profile minimal; \
    rustup toolchain install nightly-2020-03-22; \
    rustup default nightly-2020-03-22; \
    apt-get update; \
    apt-get install -y \
    cmake \
    libgflags-dev \
    libzmq3-dev \
    libssl1.1 \
    libprotobuf10 \
    libcurl4-openssl-dev \
    pkg-config \
    clang; \
    rm -rf /var/lib/apt/lists/*

ARG SGX_MODE=HW
ARG NETWORK_ID=ab
