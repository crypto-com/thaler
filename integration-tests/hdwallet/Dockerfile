FROM baiduxlab/sgx-rust:1804-1.0.9
LABEL maintainer="Crypto.com"

RUN echo 'source /opt/sgxsdk/environment' >> /root/.docker_bashrc 
RUN echo 'source /root/.cargo/env' >> /root/.docker_bashrc
RUN apt-get update 
RUN apt-get install -y --no-install-recommends libzmq3-dev rsync 
RUN rm -rf /var/lib/apt/lists/*
RUN apt update
RUN apt install wget curl -y
RUN apt install python3 libssl-dev libcurl4-openssl-dev libelf-dev libdw-dev  gcc binutils-dev libc6-dev -y
RUN apt install pkg-config -y
RUN apt install build-essential -y
RUN apt-get install cmake libgflags-dev libzmq3-dev pkg-config -y
RUN apt-get install --no-install-recommends libssl-dev libzmq3-dev -y
ENV SGX_MODE=SW
ENV NETWORK_ID=ab
ENV APP_PORT=25933
ENV TX_ENCLAVE_STORAGE=/enclave-storage
ENV RUSTFLAGS "-Ctarget-feature=+aes,+ssse3"
COPY . .
CMD ["date"]
CMD ["sleep","infinity"]

