FROM baiduxlab/sgx-rust:1804-1.0.9
LABEL maintainer="Crypto.com"

ARG SGX_MODE=SW
ARG NETWORK_ID

ENV SGX_MODE=${SGX_MODE}
ENV NETWORK_ID=${NETWORK_ID}
ENV APP_PORT=25933
ENV TX_ENCLAVE_STORAGE=/enclave-storage

RUN echo 'source /opt/sgxsdk/environment' >> /root/.docker_bashrc && \
    echo 'source /root/.cargo/env' >> /root/.docker_bashrc

RUN apt-get update && \
    apt-get install -y --no-install-recommends libzmq3-dev rsync && \
    rm -rf /var/lib/apt/lists/*

COPY . .

RUN ./chain-tx-enclave/tx-validation/make.sh

WORKDIR /root/chain-tx-enclave/tx-validation/bin

CMD ["../entrypoint.sh"]
