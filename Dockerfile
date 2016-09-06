FROM ubuntu:16.04

RUN mkdir -p /src
WORKDIR /src
ADD . /src
# This is ugly, however, keeping it in one command cuts the resultant image
# size in half
RUN apt update && apt install -y openssl libssl-dev build-essential && \
    ./configure && \
    make install && \
    rm -rf /src && \
    apt remove --quiet -y libssl-dev build-essential && \
    apt autoremove -y && \
    apt clean -y && \
    apt autoclean -y && \
    rm -rf /var/lib/apt /tmp/* /var/tmp/*
