FROM baiduxlab/sgx-rust:1804-1.1.0
LABEL maintainer="Crypto.com"

RUN echo 'source /opt/sgxsdk/environment' >> /root/.docker_bashrc && \
    echo 'source /root/.cargo/env' >> /root/.docker_bashrc

RUN apt-get update && \
    apt-get install -y --no-install-recommends libzmq3-dev clang && \
    rm -rf /var/lib/apt/lists/*

ARG SGX_MODE=SW
ARG NETWORK_ID

ENV SGX_MODE=${SGX_MODE}
ENV NETWORK_ID=${NETWORK_ID}
ENV APP_PORT=25933
ENV TX_ENCLAVE_STORAGE=/enclave-storage

COPY . .

RUN ./chain-tx-enclave/tx-validation/make.sh && cp ./chain-tx-enclave/tx-validation/entrypoint.sh ./target/debug/

WORKDIR ./target/debug

CMD ["./entrypoint.sh"]
