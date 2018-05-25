FROM debian:stretch
LABEL maintainer="Monoeci Developers <dev@monoeci.io>"
LABEL description="Dockerised MonoeciCore, built from Travis"

RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -fr /var/cache/apt/*

COPY bin/* /usr/bin/
