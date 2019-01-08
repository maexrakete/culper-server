FROM ubuntu:18.04

WORKDIR /

RUN apt-get update\
    && apt-get install -y git rustc cargo clang make pkg-config nettle-dev libssl-dev capnproto libsqlite3-dev\
    && rm -rf /var/cache/apk/*

RUN mkdir /config

COPY target/release/culper-server /usr/bin/culper-server

RUN chmod +x /usr/bin/culper-server

VOLUME ["/config"]

EXPOSE 8080
ENTRYPOINT ["/usr/bin/culper-server", "--home=/config"]
