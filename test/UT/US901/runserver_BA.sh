#!/bin/sh

# Starts EST server using HTTP Basic Authentication

export EST_TRUSTED_CERTS=CA/trustedcerts.crt
export EST_CACERTS_RESP=CA/estCA/cacert.crt
export EST_OPENSSL_CACONFIG=CA/estExampleCA.cnf

../../example/server/estserver -p 8088 -c CA/estCA/private/estservercertandkey.pem -k CA/estCA/private/estservercertandkey.pem -r estrealm -d 60 -v
