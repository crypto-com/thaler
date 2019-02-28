FROM baiduxlab/sgx-rust:1804-1.0.5 

MAINTAINER cryptocom

WORKDIR /root

RUN rm -rf /root/sgx

RUN git clone https://github.com/baidu/rust-sgx-sdk.git sgx -b v1.0.6

RUN apt-get update && \
    apt-get install -y --no-install-recommends libzmq3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN echo '/opt/intel/libsgx-enclave-common/aesm/aesm_service &' >> /root/.bashrc
