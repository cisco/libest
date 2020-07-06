#!/bin/bash

#
# Pete Beal
# Copyright 2018, Cisco Systems, Inc
#
#
# Sets variables and config for the MASA 
# Provides common helper functions
#

# make bash exit if an uninitialized variable is used
set -u

# Base variables for CA's used. These are global. :(
# also note that these must match the equivalent settings
# within each associated config file

# This first section defines the values for the MASA identity to be used for testing
export EST_OPENSSL_MASA_CACNF=masa_ExampleCA.cnf
EST_OPENSSL_MASA_CADIR=masaCA
export EST_OPENSSL_MASA_CACERT=$EST_OPENSSL_MASA_CADIR/cacert.crt
EST_OPENSSL_MASA_CAPRIVDIR=$EST_OPENSSL_MASA_CADIR/private
EST_OPENSSL_MASA_CANEWCERTSDIR=$EST_OPENSSL_MASA_CADIR/newcerts
EST_OPENSSL_MASA_CADATABASE=$EST_OPENSSL_MASA_CADIR/index.txt
EST_OPENSSL_MASA_CASERIAL=$EST_OPENSSL_MASA_CADIR/serial
EST_OPENSSL_MASA_CAPRIVKEY=$EST_OPENSSL_MASA_CAPRIVDIR/cakey.pem
EST_OPENSSL_MASA_CAPRIVKEYPARAM=$EST_OPENSSL_MASA_CAPRIVDIR/cakeyparam.pem
EST_OPENSSL_MASA_CASUBJ="/CN=MASA_CA"

EST_OPENSSLCMD_MASA_CAECPARAMSFILE=$EST_OPENSSL_MASA_CADIR/prime256v1.pem
# if you want to use EC certificates set the ..._NEWKEY_PARAM like this:
EST_OPENSSLCMD_MASA_CANEWKEY_PARAM="-newkey ec:$EST_OPENSSLCMD_MASA_CAECPARAMSFILE"
#EST_OPENSSLCMD_MASA_CANEWKEY_PARAM=" "

# This section defines a set of values for an alternate MASA identity to be 
# used for ERROR testing
export EST_MASA_ALT_MASA_CACNF=masa_estExampleCA.cnf
EST_MASA_ALT_CADIR=masaCA.altid
export EST_MASA_ALT_CACERT=$EST_MASA_ALT_CADIR/cacert.crt
EST_MASA_ALT_CAPRIVDIR=$EST_MASA_ALT_CADIR/private
EST_MASA_ALT_CANEWCERTSDIR=$EST_MASA_ALT_CADIR/newcerts
EST_MASA_ALT_CADATABASE=$EST_MASA_ALT_CADIR/index.txt
EST_MASA_ALT_CASERIAL=$EST_MASA_ALT_CADIR/serial
EST_MASA_ALT_CAPRIVKEY=$EST_MASA_ALT_CAPRIVDIR/cakey.pem
EST_MASA_ALT_CAPRIVKEYPARAM=$EST_MASA_ALT_CAPRIVDIR/cakeyparam.pem
EST_MASA_ALT_CASUBJ="/CN=MASA_CA"

EST_MASA_ALTCMD_CAECPARAMSFILE=$EST_MASA_ALT_CADIR/prime256v1.pem
# if you want to use EC certificates set the ..._NEWKEY_PARAM like this:
EST_MASA_ALTCMD_CANEWKEY_PARAM="-newkey ec:$EST_MASA_ALTCMD_CAECPARAMSFILE"
#EST_MASA_ALTCMD_CANEWKEY_PARAM=" "

OPENSSLCMD=openssl
EST_OPENSSL_CACNF=estExampleCA.cnf

function logandexit ()
{
    echo "###########..EXIT..##########"           >> $EST_LOGGING
    echo "SCRIPT $EST_SCRIPTNAME EXIT: $1 ($2)"    >> $EST_LOGGING
    echo "###########^^EXIT^^##########"           >> $EST_LOGGING
    echo " "                                       >> $EST_LOGGING
    exit $2
}

function iferrorlogandexit ()
{
    if [ $? -ne 0 ] ; then
       logandexit "$1" "$2" 
    fi
}

function dumpheadersandcontent ()
{
    echo "Headers:"                  >> $EST_LOGGING
    cat "$1"                         >> $EST_LOGGING
    echo "/Headers"                  >> $EST_LOGGING
    if [ -n "$2" ] ; then 
        echo "Content:"              >> $EST_LOGGING
        if [ -e $2 ] ; then 
            cat "$2"                 >> $EST_LOGGING
        fi
        echo "/Content"              >> $EST_LOGGING
    fi
}

# <name> header-to-search-for file-to-look-in msg-to-log additional-file-to-log
function iferrorheaderslogandexit ()
{
    grep "$1" "$2" > /dev/null
    if [ $? -ne 0 ] 
    then
        dumpheadersandcontent $2 $4
        logandexit "Header ERROR: $3" 1
    fi 
}

# TODO: support multiple certificates in pkcs7 responses (e.g. ca chains)
# puts a (single) certificate into a degenerate pkcs7
function cert2pkcs72stdout ()
{
    echo "Content-Type: application/pkcs7-mime"
    echo ""
    $OPENSSLCMD crl2pkcs7 -certfile $1 -nocrl
}

###############################################################
##### Function: Combine files
###############################################################
function combinefiles ()
{
    cat $1 > $3
    cat $2 >> $3
}

