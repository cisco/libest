#!/bin/bash

# default variables and config options
. ESTcommon_masa.sh

# completely clean out and re-create demoCA database directories (DESTRUCTIVE!!)
echo "#################################################################"
echo "SECURITY CONSIDERATIONS - NOTE WELL"
echo "The sample scripts used to handle EST operations are NOT"
echo "intended to provide a secure implementation. They have not"
echo "been evaluated for security, they have not had a Thread Model"
echo "reviewed, they are not particularly good about cleaning up after"
echo "themselves and they assume the data exchanged is well formed"
echo "if the cryptographic checks pass."
echo ""
echo "In short: They are not to be trusted. They provide a functional"
echo "implementation only."
echo ""
echo "Continuing will completely erase/destroy/nuke the existing estCA"
echo "Press any key..."
read -n 1
echo ""
echo "Nuking from orbit!"
echo "#################################################################"
rm -rf $EST_OPENSSL_MASA_CADIR
rm -rf $EST_MASA_ALT_CADIR

# given a base directory name this sets up a full CA for use
function createCA () 
{
    # inputs
    CREATECA_CASUBJ=$1
    CREATECA_CADIR=$2
    CREATECA_CACERT=$3
    CREATECA_CAPRIVDIR=$4
    CREATECA_CASERIAL=$5
    CREATECA_CADATABASE=$6
    CREATECA_CANEWCERTSDIR=$7
    CREATECA_CAPRIVKEY=$8
    CREATECA_NEWKEY_PARAM=$9
    CREATECA_ECPARAMSFILE=${10}

    echo "#################################################################"
    echo "####(Re)creating the directory structure and initial files" 
    echo "####for the CA: $CREATECA_CASUBJ"
    echo "#################################################################"
    echo "about to create" $CREATECA_CADIR " and " $CREATECA_CAPRIVDIR " and " $CREATECA_CANEWCERTSDIR 
    mkdir $CREATECA_CADIR
    mkdir $CREATECA_CAPRIVDIR
    mkdir $CREATECA_CANEWCERTSDIR
    echo "01" > $CREATECA_CASERIAL
    touch $CREATECA_CADATABASE
    
    # This is only needed for EC mode
    eval $OPENSSLCMD ecparam -name prime256v1 -out $CREATECA_ECPARAMSFILE
    iferrorlogandexit "Unable to build ECPARAMS file" 1

    eval $OPENSSLCMD req -new -x509 -sha256 -extensions v3_ca $CREATECA_NEWKEY_PARAM -keyout $CREATECA_CAPRIVKEY -out $CREATECA_CACERT -nodes -subj "$CREATECA_CASUBJ" -config $EST_OPENSSL_CACNF -days 3650
    iferrorlogandexit "Unable to create \"$CREATECA_CASUBJ\" CA cert" 1
    $OPENSSLCMD x509 -sha256 -in $CREATECA_CACERT
}

# Create the main MASA identity
echo "#################################################################"
echo "####(Re)creating an initial MASA CA identity"
echo "#################################################################"
createCA $EST_OPENSSL_MASA_CASUBJ \
    $EST_OPENSSL_MASA_CADIR \
    $EST_OPENSSL_MASA_CACERT \
    $EST_OPENSSL_MASA_CAPRIVDIR \
    $EST_OPENSSL_MASA_CASERIAL \
    $EST_OPENSSL_MASA_CADATABASE \
    $EST_OPENSSL_MASA_CANEWCERTSDIR \
    $EST_OPENSSL_MASA_CAPRIVKEY \
    "$EST_OPENSSLCMD_MASA_CANEWKEY_PARAM" \
    "$EST_OPENSSLCMD_MASA_CAECPARAMSFILE" 

# Create an alternate MASA identity to use for error testing
#echo "#################################################################"
#echo "####(Re)creating an alternate MASA identity to use for error testing
#echo "#################################################################"
createCA $EST_MASA_ALT_CASUBJ \
    $EST_MASA_ALT_CADIR \
    $EST_MASA_ALT_CACERT \
    $EST_MASA_ALT_CAPRIVDIR \
    $EST_MASA_ALT_CASERIAL \
    $EST_MASA_ALT_CADATABASE \
    $EST_MASA_ALT_CANEWCERTSDIR \
    $EST_MASA_ALT_CAPRIVKEY \
    "$EST_MASA_ALTCMD_CANEWKEY_PARAM" \
    "$EST_MASA_ALTCMD_CAECPARAMSFILE"

echo "#################################################################"
echo "####Creating combined trusted cert file"
echo "#################################################################"
# merging the EST CA cert and the MASA CA cert into one file so that the est
# server can be configured to use both when validating client certificates
cat estCA/cacert.crt masaCA/cacert.crt > brski_trustedcerts.crt

echo "#################################################################"
echo "####Creating a MASA based identity for use by a BRSKI pledge"
echo "#################################################################"
# Generate a client identity to simulate what would come from a MASA
$OPENSSLCMD req -nodes -days 365 -sha256 -newkey rsa:2048 -subj '/CN=www.iotrus.com/O=IOT-R-US, Inc./C=US/ST=NC/L=RTP/serialNumber=IOTRUS-0123456789' -keyout masaCA/pledge_priv_key.pem -out masaCA/pledge_csr.pem
$OPENSSLCMD ca -config masa_ExampleCA.cnf -in masaCA/pledge_csr.pem -extensions v3_ca -out masaCA/pledge_cert.pem -batch
