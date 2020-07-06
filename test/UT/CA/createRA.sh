#!/bin/bash

# default variables and config options
EST_SCRIPTNAME=$0
EST_SERVER_DIR=estCA
EST_OPENSSL_CACNF=./estExampleRA.cnf
EST_SERVER_SUBJ="/CN=127.0.0.1"
EST_SERVER_CERTREQ=${EST_SERVER_DIR}/proxy-csr.pem
EST_SERVER_CERT=${EST_SERVER_DIR}/proxy-cert.pem
EST_SERVER_KEY=${EST_SERVER_DIR}/private/proxy-key.pem
EST_SERVER_CERTKEY=${EST_SERVER_DIR}/private/proxy-certandkey.pem
EST_ECPARMS=${EST_SERVER_DIR}/prime256v1.pem
OPENSSLCMD=openssl

function iferrorlogandexit ()
{
    if [ $? -ne 0 ] ; then
        echo "###########..EXIT..##########"
        echo "SCRIPT $EST_SCRIPTNAME EXIT: $1 ($2)"
        echo "###########^^EXIT^^##########"
        echo ""
        exit $2
    fi
}

# Create a certificate for our est server
echo "#################################################################"
echo "####(Re)creating a certificate for our RA to use"
echo "#################################################################"
# re-using the same NEWKEY_PARAM as is used for our CA
eval $OPENSSLCMD req -new -nodes -out $EST_SERVER_CERTREQ -newkey ec:$EST_ECPARMS -keyout $EST_SERVER_KEY -subj $EST_SERVER_SUBJ -config $EST_OPENSSL_CACNF
iferrorlogandexit "Unable to create est server CSR" 1
$OPENSSLCMD ca -out $EST_SERVER_CERT -batch -config $EST_OPENSSL_CACNF -infiles $EST_SERVER_CERTREQ
iferrorlogandexit "Unable to create RA certificate" 1
$OPENSSLCMD x509 -in $EST_SERVER_CERT -text
cat $EST_SERVER_KEY $EST_SERVER_CERT > $EST_SERVER_CERTKEY
