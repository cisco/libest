#!/bin/sh

# Starts EST server using no HTTP Authentication

export EST_TRUSTED_CERTS=CA/trustedcerts.crt
export EST_CACERTS_RESP=CA/estCA/cacert.crt
export EST_OPENSSL_CACONFIG=CA/estExampleCA.cnf

../../example/server/estserver -n -p 8086 -c CA/estCA/private/estservercertandkey.pem -k CA/estCA/private/estservercertandkey.pem -r estrealm -d 60 -v
