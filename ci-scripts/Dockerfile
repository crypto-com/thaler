FROM baiduxlab/sgx-rust:1804-1.1.0
LABEL maintainer="Crypto.com"

RUN echo 'source /opt/sgxsdk/environment' >> /root/.docker_bashrc && \
    echo 'source /root/.cargo/env' >> /root/.docker_bashrc

RUN apt-get update && \
    apt-get install -y --no-install-recommends libzmq3-dev clang && \
    rm -rf /var/lib/apt/lists/*

ARG SGX_MODE=HW
ARG NETWORK_ID=ab
