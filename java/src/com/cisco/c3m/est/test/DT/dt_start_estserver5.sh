#!/bin/sh
# Name: dt_start_estserver5.sh
#
# Purpose: Start estserver for use with Java EST Client simple reenroll testing
# For use with ESTClientReEnrollTestNonFIPS.java tests
# and mainly just uses different ports so as
# not to conflict with other testing

echo "Starting dt_start_estserver5.sh ..."

cd $WORKSPACE/example/server

# this is the main estserver instance that should be used for simple reenrolls
$WORKSPACE/install/bin/estserver -o -p $EST_DT5_PORT1 --srp passwd.srpv -c estCA/private/estservercertandkey.pem -k estCA/private/estservercertandkey.pem -r estrealm -v -6 -d 60 &
sleep 3

echo "dt_start_estserver5.sh is complete..."
exit 0
