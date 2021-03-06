FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    git \
    automake \
    autoconf \
    libtool \
    pkg-config \
    build-essential \
    libssl-dev \
    sqlite3 \
    libsqlite3-dev \
    cmake \
    libseccomp-dev

# Builging sfthsmv2/installing
RUN git clone https://github.com/opendnssec/SoftHSMv2.git && \
    cd SoftHSMv2 && \
    sh autogen.sh && \
    ./configure --disable-non-paged-memory --with-objectstore-backend-db && \
    make && \
    make install && \
    mkdir -p /softhsm/tokens
    # cp src/bin/util/softhsm2-util /usr/bin/ && \
    # mkdir -p /usr/local/lib/softhsm && \
    # cp -p src/lib/.libs/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so

RUN echo "directories.tokendir = /softhsm/tokens" > /etc/softhsm2.conf && \
    echo "objectstore.backend = db" >> /etc/softhsm2.conf && \
    echo "log.level = INFO" >> /etc/softhsm2.conf && \
    echo "slots.removable = false" >> /etc/softhsm2.conf 

RUN softhsm2-util --init-token --slot 0 --label "lamassuHSM" --pin 1234 --so-pin 0000

# building/installing pkcs11-proxy
RUN git clone https://github.com/SUNET/pkcs11-proxy && \
    cd pkcs11-proxy && \
    cmake . && make && make install && cp pkcs11-daemon /usr/local/bin/

COPY test.psk /test.psk

EXPOSE 5657
ENV PKCS11_DAEMON_SOCKET="tls://0.0.0.0:5657"
ENV PKCS11_PROXY_TLS_PSK_FILE="/test.psk"
ENTRYPOINT  [ "/usr/local/bin/pkcs11-daemon", "/usr/local/lib/softhsm/libsofthsm2.so" ]