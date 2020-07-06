#!/bin/sh
# Name: dt_start_estserver3.sh
#
# Purpose: Start estserver for use with Java EST Client get cacerts testing
# For use with CACertsTestNonFIPS.java tests
# and mainly just uses different ports so as
# not to conflict with dt_start_estserver2.sh

echo "Starting dt_start_estserver3.sh ..."

cd $WORKSPACE/example/server

# this is the main estserver instance that should be used for simple enrolls
$WORKSPACE/install/bin/estserver -o -p $EST_CACERTS_PORT_NF --srp passwd.srpv -c estCA/private/estservercertandkey.pem -k estCA/private/estservercertandkey.pem -r estrealm -v -6 -d 60 &
sleep 3

echo "dt_start_estserver3.sh is complete..."
exit 0
