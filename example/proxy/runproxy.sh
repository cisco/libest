#!/bin/sh

${OPENSSL_DIR:=/usr/local/ssl}
${EST_DIR:=/usr/local/est}

export EST_TRUSTED_CERTS=../server/trustedcerts.crt
export EST_CACERTS_RESP=../server/estCA/cacert.crt
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$OPENSSL_DIR/lib:$EST_DIR/lib

./estproxy -c ./proxy-cert.pem -k ./proxy-key.pem -s 127.0.0.1 -p 8085 -r estrealm -v 
