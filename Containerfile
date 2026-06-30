FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    wireguard-tools \
    iproute2 \
    iputils-ping \
    procps \
    nftables \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
RUN pip install /src
