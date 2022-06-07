# SoftHSM v2 + Golang

SoftHSM v2: <https://github.com/opendnssec/SoftHSMv2>

PKCS11 Proxy + TLS: <https://github.com/SUNET/pkcs11-proxy>

PKCS11 Golang lib: `github.com/miekg/pkcs11`

crypto/signer PKCS11-based Golang lib: `github.com/ThalesIgnite/crypto11`

## PoC setup

### Regenerate PreSharedKey test.psk
```
psk=$(openssl rand -base64 18 | xxd -p)
echo "test:$psk" > test.psk
```
### HSM Server Build
```
docker build -f softhsm-v2.Dockerfile -t softhsmv2 . 
```
### PKC11 Client Build
```
docker build -f pkcs11-client.Dockerfile -t pkcs11-client .
```
### HSM Server Run
```
docker run -it -p 5657:5657 --name hsm softhsmv2
```
### PKC11 Client Run
```
docker run -it --link=hsm:hsm pkcs11-client bash
```
```
./pkcs11-go-client -module=/usr/local/lib/libpkcs11-proxy.so -pin=1234
./crypto11-go-client -module /usr/local/lib/libpkcs11-proxy.so -token-label=lamassuHSM -pin=1234
pkcs11-tool --module=/usr/local/lib/libpkcs11-proxy.so -L
```