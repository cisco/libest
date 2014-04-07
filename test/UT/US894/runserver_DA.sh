#!/bin/sh

# Starts EST server using HTTP Digest Authentication

export EST_TRUSTED_CERTS=CA/trustedcerts.crt
export EST_CACERTS_RESP=CA/estCA/cacert.crt
export EST_OPENSSL_CACONFIG=CA/estExampleCA.cnf

../../example/proxy/estproxy -p 9232 -s 127.0.0.1 -l 8087 -h -c CA/estCA/private/estservercertandkey.pem -k CA/estCA/private/estservercertandkey.pem -r estrealm -v
