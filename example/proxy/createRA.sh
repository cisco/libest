#!/bin/bash

# default variables and config options
EST_SCRIPTNAME=$0
EST_OPENSSL_CACNF=./estExampleCA.cnf
EST_SERVER_SUBJ="/CN=127.0.0.1"
EST_SERVER_CERTREQ=tmp/proxy-csr.pem
EST_SERVER_CERT=proxy-cert.pem
EST_SERVER_KEY=proxy-key.pem
EST_ECPARMS=tmp/ec.pem
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

if [ -e tmp ] ; then 
    rm -r tmp 
fi
mkdir tmp

eval $OPENSSLCMD ecparam -out $EST_ECPARMS -name prime256v1 -genkey
eval $OPENSSLCMD ecparam -in $EST_ECPARMS -check

# Create a certificate for our est server
# TODO: add extension for est server
echo "#################################################################"
echo "####(Re)creating a certificate for our RA to use"
echo "#################################################################"
# re-using the same NEWKEY_PARAM as is used for our CA
eval $OPENSSLCMD req -new -nodes -out $EST_SERVER_CERTREQ -newkey ec:$EST_ECPARMS -keyout $EST_SERVER_KEY -subj $EST_SERVER_SUBJ -config $EST_OPENSSL_CACNF
iferrorlogandexit "Unable to create est server CSR" 1
$OPENSSLCMD ca -out $EST_SERVER_CERT -batch -config $EST_OPENSSL_CACNF -infiles $EST_SERVER_CERTREQ
iferrorlogandexit "Unable to create RA certificate" 1
$OPENSSLCMD x509 -in $EST_SERVER_CERT -text
