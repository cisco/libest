#!/bin/sh

# Starts EST server using HTTP Basic Authentication
# This uses the cert store in the example/server directory

export EST_TRUSTED_CERTS=../../example/server/trustedcerts.crt
export EST_CACERTS_RESP=../../example/server/estCA/cacert.crt 
export EST_OPENSSL_CACONFIG=US901/estExampleCA.cnf

../../example/server/estserver -p 8897 -c ../../example/server/estCA/private/estservercertandkey.pem -k ../../example/server/estCA/private/estservercertandkey.pem -r estrealm -d 90 -v
