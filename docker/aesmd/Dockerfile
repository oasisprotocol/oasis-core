FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -qq curl lsb-release gpg

ADD intel-sgx-deb.gpg /etc/apt/trusted.gpg.d

RUN echo "deb https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -cs) main" > /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update -qq && apt-get install -qq sgx-aesm-service libsgx-aesm-launch-plugin libsgx-aesm-epid-plugin

ENV AESM_PATH=/opt/intel/sgx-aesm-service/aesm
ENV LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm

WORKDIR /opt/intel/sgx-aesm-service/aesm

ENTRYPOINT /opt/intel/sgx-aesm-service/aesm/aesm_service

