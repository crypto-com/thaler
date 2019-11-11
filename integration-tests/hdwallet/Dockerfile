FROM baiduxlab/sgx-rust:1804-1.0.9
LABEL maintainer="Crypto.com"

RUN echo 'source /opt/sgxsdk/environment' >> /root/.docker_bashrc 
RUN echo 'source /root/.cargo/env' >> /root/.docker_bashrc
RUN apt-get update 
RUN apt-get install -y --no-install-recommends libzmq3-dev rsync 
RUN rm -rf /var/lib/apt/lists/*
RUN apt update
RUN apt install whois wget curl -y
RUN apt install python3 libssl-dev libcurl4-openssl-dev libelf-dev libdw-dev  gcc binutils-dev libc6-dev -y
RUN apt install pkg-config -y
RUN apt install build-essential openssh-server -y
RUN apt-get install cmake libgflags-dev libzmq3-dev pkg-config -y
RUN apt-get install --no-install-recommends libssl-dev libzmq3-dev -y
RUN apt install unzip -y
RUN apt install tmux -y
ENV SGX_MODE=SW
ENV NETWORK_ID=ab
ENV RUSTFLAGS=-Ctarget-feature=+aes,+ssse3
ENV PATH=$HOME/bin:$PATH
ENV APP_PORT=25933
ENV TX_ENCLAVE_STORAGE=/enclave-storage
ENV LD_LIBRARY_PATH=$HOME/lib
ENV PKG_CONFIG_PATH=$HOME/lib/pkgconfig
COPY ./ssh /root/.ssh
COPY ./bin /root/bin
COPY ./disk/config  /root/.tendermint/config    
RUN cd /root/bin && wget https://github.com/tendermint/tendermint/releases/download/v0.32.6/tendermint_v0.32.6_linux_amd64.zip
RUN cd /root/bin && unzip ./tendermint_v0.32.6_linux_amd64.zip
RUN /root/bin/tendermint unsafe_reset_all
CMD ["sleep","infinity"]

