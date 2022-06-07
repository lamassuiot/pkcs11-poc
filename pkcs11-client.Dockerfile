FROM golang:1.18
WORKDIR /app
COPY . .
WORKDIR /app
ENV GOSUMDB=off
RUN go build -o crypto11-go-client crypto11/crypto11-main.go
RUN go build -o pkcs11-go-client pkcs11/pkcs11-main.go


FROM ubuntu:18.04

# Dependencies for pkcs11-proxy and opensc for pkcs11-tool
RUN apt-get update && \
    apt-get install -y  git-core make cmake libssl-dev libseccomp-dev opensc

RUN git clone https://github.com/SUNET/pkcs11-proxy && \
    cd pkcs11-proxy && \
    cmake . && make && make install

COPY test.psk /root/test.psk
ENV PKCS11_PROXY_TLS_PSK_FILE="/root/test.psk"
ENV PKCS11_PROXY_SOCKET="tls://hsm:5657"

COPY --from=0 /app/crypto11-go-client .
COPY --from=0 /app/pkcs11-go-client .