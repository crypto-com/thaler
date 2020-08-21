FROM baiduxlab/sgx-rust:1804-1.1.2
LABEL maintainer="Crypto.com"

ENV PATH=/root/.cargo/bin:/root/.local/bin:$PATH
ENV RUST_BACKTRACE=1
ENV RUSTFLAGS "-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"

RUN echo 'source /opt/sgxsdk/environment' >> /root/.docker_bashrc && \
    echo 'source /root/.cargo/env' >> /root/.docker_bashrc

RUN set -e; \
    apt-get update; \
    apt-get install -y \
        cmake \
        libgflags-dev \
        libudev-dev \
        libssl1.1 \
        libprotobuf10 \
        libcurl4-openssl-dev \
        pkg-config \
        xz-utils; \
    wget -q https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.0-rc1/clang+llvm-11.0.0-rc1-x86_64-linux-gnu-ubuntu-16.04.tar.xz; \
    tar -xf clang+llvm-11.0.0-rc1-x86_64-linux-gnu-ubuntu-16.04.tar.xz --strip-components=1 -C /usr/; \
    update-alternatives --install /usr/bin/cc cc /usr/bin/clang 30; \
    ln -s /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /usr/lib/x86_64-linux-gnu/libstdc++.so; \
    rm -rf /var/lib/apt/lists/*

# fortanix environment
RUN set -e; \
    rustup update; \
    cargo install fortanix-sgx-tools sgxs-tools cargo-crate-type

ARG SGX_MODE=HW
ARG NETWORK_ID=ab
