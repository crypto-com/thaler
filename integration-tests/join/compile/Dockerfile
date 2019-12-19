FROM cryptocom/chain:latest
LABEL maintainer="Crypto.com"
RUN echo 'source /opt/sgxsdk/environment' >> /root/.docker_bashrc 
RUN echo 'source /root/.cargo/env' >> /root/.docker_bashrc
RUN rm -rf /var/lib/apt/lists/*
RUN apt-get clean
RUN sed -i 's/old-releases.ubuntu.com/ftp.daum.net/g' /etc/apt/sources.list
RUN sed -i 's/security.ubuntu.com/ftp.daum.net/g' /etc/apt/sources.list
RUN sed -i 's/archive.ubuntu.com/ftp.daum.net/g' /etc/apt/sources.list
RUN apt-get update
RUN apt install -y --no-install-recommends whois wget curl python3 libssl-dev libcurl4-openssl-dev libelf-dev libdw-dev  gcc binutils-dev libc6-dev pkg-config build-essential openssh-server cmake libgflags-dev libzmq3-dev pkg-config libssl-dev libzmq3-dev  unzip  tmux clang 
ENV SGX_MODE=SW
ENV NETWORK_ID=AB
ENV RUSTFLAGS=-Ctarget-feature=+aes,+ssse3
ENV PATH=$HOME/bin:$PATH
ENV APP_PORT=25933
ENV TX_ENCLAVE_STORAGE=/enclave-storage
ENV LD_LIBRARY_PATH=$HOME/lib
ENV PKG_CONFIG_PATH=$HOME/lib/pkgconfig
RUN mkdir /root/bin
RUN cd /root/bin && wget https://github.com/tendermint/tendermint/releases/download/v0.32.6/tendermint_v0.32.6_linux_amd64.zip
RUN cd /root/bin && unzip ./tendermint_v0.32.6_linux_amd64.zip
RUN /root/bin/tendermint unsafe_reset_all

